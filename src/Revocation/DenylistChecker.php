<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Revocation;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Wollerp\AuthClient\Exceptions\TokenRevokedException;
use Wollerp\AuthClient\Token\Claims;

/**
 * LAYER 2 of CONTRACT §2 — step 8, one indexed query against the local table:
 *
 *   SELECT 1 FROM revoked_tokens WHERE sid = ? OR jti = ?
 *
 * Local, because a network call to the auth server on every request would make
 * the auth server a hard dependency of every product's availability, which is
 * the entire thing offline validation exists to avoid.
 *
 * `expires_at` is deliberately NOT part of the predicate. Pruning removes rows
 * once the last token they could match has expired; adding
 * `AND expires_at > NOW()` would let a clock skew between the pruning job and
 * the request host resurrect a revoked session for a few seconds.
 */
final class DenylistChecker
{
    public function __construct(
        private readonly ConnectionInterface $connection,
        private readonly string $table = 'revoked_tokens',
    ) {}

    public function isRevoked(Claims $claims): bool
    {
        return $this->matches($claims->sid(), $claims->jti());
    }

    /**
     * @throws TokenRevokedException
     */
    public function assertNotRevoked(Claims $claims): void
    {
        if ($this->isRevoked($claims)) {
            throw TokenRevokedException::make();
        }
    }

    public function matches(?string $sid, ?string $jti): bool
    {
        $sid = $sid !== '' ? $sid : null;
        $jti = $jti !== '' ? $jti : null;

        if ($sid === null && $jti === null) {
            return false;
        }

        return $this->connection->table($this->table)
            ->where(function (Builder $query) use ($sid, $jti): void {
                if ($sid !== null) {
                    $query->orWhere('sid', '=', $sid);
                }

                if ($jti !== null) {
                    $query->orWhere('jti', '=', $jti);
                }
            })
            ->exists();
    }

    /**
     * Used by the auth → product `POST /api/v1/internal/revoke` handler
     * (CONTRACT §5) once that route has passed HMAC verification.
     *
     * ── `$notAfter` accepts what the auth server actually sends ─────────────
     * App\Jobs\DispatchRevocationWebhook posts `not_after` as an ISO-8601
     * STRING ("2026-09-15T12:20:00+00:00"), not a unix integer. A handler that
     * forwards `$request->input('not_after')` straight in — which is the
     * documented handler — would either raise a TypeError under
     * `declare(strict_types=1)`, or, without it, coerce "2026-09-15T…" to the
     * int 2026 and stamp `expires_at` in January 1970. The second failure is
     * the dangerous one: the row is still written, so the revocation appears to
     * work, and then the next prune() deletes it and the session is live again.
     * So this normalises rather than narrows.
     *
     * ── Idempotent, because delivery is retried ─────────────────────────────
     * The webhook has six attempts and a backoff schedule; a receiver that
     * plain-inserts accumulates a duplicate row per retry. Re-revoking the same
     * (sid, jti) pair updates the existing row instead.
     */
    public function revoke(
        ?string $sid,
        ?string $jti,
        int|string|\DateTimeInterface|null $notAfter = null,
        ?string $reason = null,
    ): void {
        $sid = ($sid === null || $sid === '') ? null : $sid;
        $jti = ($jti === null || $jti === '') ? null : $jti;

        if ($sid === null && $jti === null) {
            return;
        }

        $values = [
            'expires_at' => self::normaliseTimestamp($notAfter),
            // CONTRACT §6 caps `reason` at VARCHAR(32). Truncate rather than let
            // an over-long value raise and abort the whole revocation: the
            // denylist row is security-critical, the label on it is not.
            'reason' => self::normaliseReason($reason),
        ];

        $existing = $this->connection->table($this->table)
            ->when($sid === null, fn (Builder $q): Builder => $q->whereNull('sid'))
            ->when($sid !== null, fn (Builder $q): Builder => $q->where('sid', '=', $sid))
            ->when($jti === null, fn (Builder $q): Builder => $q->whereNull('jti'))
            ->when($jti !== null, fn (Builder $q): Builder => $q->where('jti', '=', $jti));

        if ((clone $existing)->exists()) {
            $existing->update($values);

            return;
        }

        $this->connection->table($this->table)->insert($values + [
            'sid' => $sid,
            'jti' => $jti,
            'created_at' => date('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Unix int, ISO-8601 string, or DateTimeInterface — all to `Y-m-d H:i:s`.
     * An unparsable value becomes null, which means "never prune this row":
     * keeping a revocation forever is the safe direction to fail.
     */
    private static function normaliseTimestamp(int|string|\DateTimeInterface|null $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        if ($value instanceof \DateTimeInterface) {
            return $value->format('Y-m-d H:i:s');
        }

        if (is_int($value)) {
            return date('Y-m-d H:i:s', $value);
        }

        // A bare digit string is a unix timestamp; anything else is a date.
        $parsed = ctype_digit($value) ? (int) $value : strtotime($value);

        return $parsed === false ? null : date('Y-m-d H:i:s', $parsed);
    }

    private static function normaliseReason(?string $reason): ?string
    {
        if ($reason === null || $reason === '') {
            return null;
        }

        return substr($reason, 0, 32);
    }

    /**
     * @return int rows removed
     */
    public function prune(?int $before = null): int
    {
        return $this->connection->table($this->table)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<', date('Y-m-d H:i:s', $before ?? time()))
            ->delete();
    }
}
