<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Console;

use Illuminate\Console\Command;
use Illuminate\Http\Client\Factory as HttpFactory;
use Symfony\Component\Console\Attribute\AsCommand;
use Throwable;
use Wollerp\AuthClient\Hmac\Signer;
use Wollerp\AuthClient\Mirror\MirrorSynchroniser;
use Wollerp\AuthClient\Support\CaBundle;

/**
 * CONTRACT §4 layer 3 — the backstop. Nightly reconcile plus the initial
 * backfill, over the §5 service plane:
 *
 *   GET /api/v1/internal/users?since=
 *
 * Layers 1 (token upsert) and 2 (webhook) cover active users and live changes.
 * This covers everything else: users who have not logged in since a change,
 * webhooks that were dropped while the product was down, and the first import.
 *
 * Schedule it daily. It is idempotent and never rolls a row backwards.
 *
 * The #[AsCommand] attribute is load-bearing, not decoration.
 * Illuminate\Console\Application::resolve() only defers instantiation for
 * commands that carry it; without it Laravel calls make() on this class at
 * console boot, which constructs the Signer, which refuses to exist without an
 * HMAC secret — so a product that has not yet been issued one could not run
 * `php artisan config:cache`, or any other artisan command, at all.
 */
#[AsCommand(name: 'users:sync')]
final class SyncUsersCommand extends Command
{
    /** CONTRACT §5.4: "limit — default 500, max 1000." */
    public const MAX_SERVER_LIMIT = 1000;

    protected $signature = 'users:sync
        {--since= : Only users changed at or after this time (any strtotime-parsable value). Omit for a full backfill.}
        {--per-page= : Page size requested from the auth server.}
        {--max-pages=10000 : Safety stop, in case the server never stops handing out cursors.}
        {--dry-run : Fetch and report without writing to the mirror.}';

    protected $description = 'Reconcile users_mirror against the Wollerp auth server.';

    public function __construct(
        private readonly HttpFactory $http,
        private readonly MirrorSynchroniser $mirror,
        private readonly Signer $signer,
        private readonly string $baseUrl,
        private readonly string $endpoint,
        private readonly int $perPage,
        private readonly int $timeout,
        private readonly string $caBundle = '',
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        $since = $this->resolveSince();

        if ($since === false) {
            $this->components->error('--since is not a parsable date/time.');

            return self::INVALID;
        }

        $dryRun = (bool) $this->option('dry-run');

        // Clamped to the server's cap rather than sent as-is. CONTRACT §5.4 says
        // "limit — default 500, max 1000", and UserSyncRequest enforces that with
        // `max:1000`, which REJECTS an over-large value with a 422 rather than
        // clamping it. An operator reaching for `--per-page=5000` to speed up a
        // backfill should get a slightly slower backfill, not a failed one.
        $perPage = min(
            self::MAX_SERVER_LIMIT,
            max(1, (int) ($this->option('per-page') ?: $this->perPage))
        );

        $maxPages = max(1, (int) $this->option('max-pages'));

        $url = rtrim($this->baseUrl, '/').'/'.ltrim($this->endpoint, '/');

        $cursor = null;
        $page = 0;
        $seen = 0;
        $written = 0;

        $this->components->info(sprintf(
            'Reconciling from %s%s%s',
            $url,
            $since !== null ? ' since '.date('c', $since) : ' (full backfill)',
            $dryRun ? ' [dry run]' : ''
        ));

        do {
            $page++;

            // The parameter is `limit`, NOT `per_page` — CONTRACT §5.3 spells the
            // endpoint as `?since=&cursor=&limit=`, and App\Http\Requests\Internal
            // \UserSyncRequest validates exactly that name. Sending `per_page` is
            // not an error on the wire: the form request ignores unknown query
            // parameters, so the server silently falls back to its own default of
            // 500 and `--per-page` becomes a no-op that looks like it worked.
            $query = array_filter([
                'since' => $since !== null ? date('c', $since) : null,
                'limit' => $perPage,
                'cursor' => $cursor,
            ], static fn (mixed $value): bool => $value !== null);

            try {
                // A GET has no body, so the signed string is "{timestamp}."
                // exactly as CONTRACT §5 specifies.
                $response = $this->http
                    ->timeout($this->timeout)
                    ->acceptJson()
                    ->withOptions(CaBundle::options($this->caBundle))
                    ->withHeaders($this->signer->headers(''))
                    ->get($url, $query);
            } catch (Throwable $exception) {
                $this->components->error('Auth server unreachable: '.$exception->getMessage());

                return self::FAILURE;
            }

            if (! $response->successful()) {
                $this->components->error(sprintf(
                    'Auth server returned HTTP %d on page %d.',
                    $response->status(),
                    $page
                ));

                return self::FAILURE;
            }

            $payload = $response->json();

            if (! is_array($payload)) {
                $this->components->error('Auth server returned a non-JSON body.');

                return self::FAILURE;
            }

            $records = $payload['data'] ?? $payload['users'] ?? [];

            if (! is_array($records)) {
                $records = [];
            }

            foreach ($records as $record) {
                if (! is_array($record)) {
                    continue;
                }

                $seen++;

                if (! $dryRun && $this->mirror->syncFromRecord($record)) {
                    $written++;
                }
            }

            $cursor = $this->nextCursor($payload);
        } while ($cursor !== null && $records !== [] && $page < $maxPages);

        if ($cursor !== null && $page >= $maxPages) {
            $this->components->warn("Stopped at the --max-pages limit of {$maxPages}; rerun to continue.");
        }

        $this->components->info(sprintf(
            '%d record(s) read over %d page(s); %d mirror row(s) written.',
            $seen,
            $page,
            $written
        ));

        return self::SUCCESS;
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function nextCursor(array $payload): ?string
    {
        $meta = $payload['meta'] ?? [];

        $cursor = $payload['next_cursor']
            ?? (is_array($meta) ? ($meta['next_cursor'] ?? null) : null);

        return is_string($cursor) && $cursor !== '' ? $cursor : null;
    }

    private function resolveSince(): int|false|null
    {
        $since = $this->option('since');

        if ($since === null || $since === '') {
            return null;
        }

        return strtotime((string) $since);
    }
}
