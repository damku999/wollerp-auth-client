<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Mirror;

use Closure;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Wollerp\AuthClient\Token\Claims;

/**
 * CONTRACT §4 — the ONLY write path into `users_mirror`.
 *
 * Three layers, each covering the previous one's failure:
 *
 *   1. Token-driven upsert (primary) — every request carries sub/uid/name/
 *      email/ver. If the local row is missing or its `version` is lower, upsert
 *      inline. No extra HTTP call. Self-heals on the user's next request.
 *   2. Webhook (secondary) — covers users who are not currently active.
 *   3. `users:sync --since=` (backstop) — nightly, plus the initial backfill.
 *
 * Layers 2 and 3 both land on syncFromRecord(); layer 1 on syncFromClaims().
 *
 * The guard: MirroredUser throws on every save and delete unless
 * isSynchronising() is true, and the only code that can make it true is the
 * private write() below. A depth counter rather than a boolean so nested calls
 * cannot close the gate early.
 */
final class MirrorSynchroniser
{
    private static int $depth = 0;

    /**
     * @param  Closure(): int|null  $clock
     */
    public function __construct(
        private readonly Model $model,
        private readonly bool $enabled = true,
        private readonly ?Closure $clock = null,
    ) {}

    public static function isSynchronising(): bool
    {
        return self::$depth > 0;
    }

    /**
     * Layer 1. Runs on every authenticated request; writes only when `ver`
     * drifted, so the steady-state cost is one primary-key lookup.
     *
     * @return bool whether a write happened
     */
    public function syncFromClaims(Claims $claims): bool
    {
        if (! $this->enabled || $claims->uid() <= 0) {
            return false;
        }

        $existing = $this->find($claims->uid());

        if ($existing !== null && (int) $existing->getAttribute('version') >= $claims->ver()) {
            return false;
        }

        $attributes = [
            'auth_user_uuid' => $claims->sub(),
            'name' => $claims->name(),
            'email' => $claims->email(),
            'version' => $claims->ver(),
            'email_verified_at' => $this->resolveVerifiedAt($claims, $existing),
            'synced_at' => $this->timestamp(),
        ];

        // `status` is deliberately absent. The token does not carry it
        // (CONTRACT §1), so a token-driven upsert must not overwrite a status
        // set by the webhook or the nightly reconcile — a suspended user would
        // silently flip back to active on their next request.

        $this->write(fn () => $this->model->newQuery()->updateOrCreate(
            ['auth_user_id' => $claims->uid()],
            $attributes,
        ));

        return true;
    }

    /**
     * Layers 2 and 3. A full record straight from the auth server, so unlike
     * the token path this one owns `status` as well.
     *
     * @param  array<string, mixed>  $record
     * @return bool whether a write happened
     */
    public function syncFromRecord(array $record): bool
    {
        $id = (int) ($record['auth_user_id'] ?? $record['id'] ?? 0);

        if ($id <= 0) {
            return false;
        }

        $version = (int) ($record['version'] ?? $record['ver'] ?? 0);
        $existing = $this->find($id);

        if ($existing !== null && (int) $existing->getAttribute('version') > $version) {
            // An older snapshot than what we already hold. A slow page of a
            // backfill must never roll the mirror backwards.
            return false;
        }

        $attributes = [
            'auth_user_uuid' => (string) ($record['auth_user_uuid'] ?? $record['uuid'] ?? $record['sub'] ?? ''),
            'name' => $this->nullableString($record['name'] ?? null),
            'email' => $this->nullableString($record['email'] ?? null),
            'status' => $this->nullableString($record['status'] ?? null),
            'email_verified_at' => $this->normaliseVerifiedAt($record),
            'version' => $version,
            'synced_at' => $this->timestamp(),
        ];

        $this->write(fn () => $this->model->newQuery()->updateOrCreate(
            ['auth_user_id' => $id],
            $attributes,
        ));

        return true;
    }

    public function find(int $authUserId): ?Model
    {
        /** @var Model|null $found */
        $found = $this->model->newQuery()->find($authUserId);

        return $found;
    }

    public function findByUuid(string $sub): ?Model
    {
        /** @var Model|null $found */
        $found = $this->model->newQuery()->where('auth_user_uuid', $sub)->first();

        return $found;
    }

    public function enabled(): bool
    {
        return $this->enabled;
    }

    /**
     * @template TReturn
     *
     * @param  Closure(): TReturn  $callback
     * @return TReturn
     */
    private function write(Closure $callback): mixed
    {
        self::$depth++;

        try {
            return $callback();
        } finally {
            // finally, not catch-and-rethrow: a failed upsert must still close
            // the gate, or one exception leaves the mirror writable for the
            // rest of the process.
            self::$depth--;
        }
    }

    /**
     * The token carries `email_verified` as a boolean; the mirror stores a
     * timestamp. Preserve the original verification time when we already have
     * one — overwriting it on every version bump would destroy the only record
     * of when verification happened.
     */
    private function resolveVerifiedAt(Claims $claims, ?Model $existing): ?string
    {
        if (! $claims->emailVerified()) {
            return null;
        }

        $current = $existing?->getAttribute('email_verified_at');

        if ($current !== null) {
            return $current instanceof DateTimeInterface
                ? $current->format('Y-m-d H:i:s')
                : (string) $current;
        }

        return $this->timestamp();
    }

    /**
     * @param  array<string, mixed>  $record
     */
    private function normaliseVerifiedAt(array $record): ?string
    {
        $value = $record['email_verified_at'] ?? null;

        if ($value === null || $value === '') {
            return isset($record['email_verified']) && filter_var($record['email_verified'], FILTER_VALIDATE_BOOL)
                ? $this->timestamp()
                : null;
        }

        if ($value instanceof DateTimeInterface) {
            return $value->format('Y-m-d H:i:s');
        }

        $parsed = strtotime((string) $value);

        return $parsed === false ? null : date('Y-m-d H:i:s', $parsed);
    }

    private function nullableString(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private function timestamp(): string
    {
        return date('Y-m-d H:i:s', $this->clock !== null ? ($this->clock)() : time());
    }
}
