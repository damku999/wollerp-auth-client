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
     * ── Every parameter is `mixed` on purpose ───────────────────────────────
     * The documented handler forwards `$request->input(...)` straight in, and
     * `input()` returns whatever was in the JSON body — which is attacker- or,
     * more realistically, bug-shaped. Under the platform's mandatory
     * `declare(strict_types=1)`, a narrower signature turns `{"sid": 12345}`
     * into a TypeError, i.e. a **500 on a service-plane call** where a 422
     * naming the field is the correct answer. Normalising here is what lets the
     * handler stay four lines and still be correct; see README for the handler
     * that returns 422 on a false return.
     *
     * Nothing is widened in what actually gets stored: a non-scalar becomes
     * null, and if that leaves neither a `sid` nor a `jti` the call writes
     * nothing and reports false.
     *
     * ── `$notAfter` accepts what the auth server actually sends ─────────────
     * App\Jobs\DispatchRevocationWebhook posts `not_after` as an ISO-8601
     * STRING ("2026-09-15T12:20:00+00:00"), not a unix integer. A handler that
     * forwards it straight in would either raise that same TypeError, or,
     * without strict types, coerce "2026-09-15T…" to the int 2026 and stamp
     * `expires_at` in January 1970. The second failure is the dangerous one:
     * the row is still written, so the revocation appears to work, and then the
     * next prune() deletes it and the session is live again.
     *
     * ── Idempotent, because delivery is retried ─────────────────────────────
     * The webhook has six attempts and a backoff schedule; a receiver that
     * plain-inserts accumulates a duplicate row per retry. Re-revoking the same
     * (sid, jti) pair updates the existing row instead.
     *
     * @return bool true when a denylist row now exists for this (sid, jti).
     *              false means the payload named neither, so there was nothing
     *              to revoke — the caller should answer 422, not 204.
     */
    public function revoke(
        mixed $sid,
        mixed $jti,
        mixed $notAfter = null,
        mixed $reason = null,
    ): bool {
        $sid = self::normaliseIdentifier($sid);
        $jti = self::normaliseIdentifier($jti);

        if ($sid === null && $jti === null) {
            return false;
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

            return true;
        }

        $this->connection->table($this->table)->insert($values + [
            'sid' => $sid,
            'jti' => $jti,
            'created_at' => gmdate('Y-m-d H:i:s'),
        ]);

        return true;
    }

    /**
     * A `sid` or `jti` off the wire, as a non-empty string or null.
     *
     * Ints are accepted and stringified rather than rejected: the claims are
     * ULIDs, but a sender that serialises one as a number is sending something
     * we can still match on, and dropping it silently would be a lost
     * revocation. Everything non-scalar — arrays, objects, booleans — becomes
     * null, because there is no defensible string for it and guessing one risks
     * writing a denylist row that matches nothing.
     */
    private static function normaliseIdentifier(mixed $value): ?string
    {
        if (is_string($value)) {
            return $value === '' ? null : $value;
        }

        if (is_int($value)) {
            return (string) $value;
        }

        if ($value instanceof \Stringable) {
            $value = (string) $value;

            return $value === '' ? null : $value;
        }

        return null;
    }

    /**
     * Unix int, ISO-8601 string, or DateTimeInterface — all to `Y-m-d H:i:s`.
     * An unparsable value becomes null, which means "never prune this row":
     * keeping a revocation forever is the safe direction to fail. That is also
     * why a non-scalar lands here rather than throwing — a rejected `not_after`
     * costs storage, a rejected revocation costs a live session.
     */
    private static function normaliseTimestamp(mixed $value): ?string
    {
        if ($value instanceof \DateTimeInterface) {
            return $value->format('Y-m-d H:i:s');
        }

        if (is_int($value)) {
            return gmdate('Y-m-d H:i:s', $value);
        }

        if (! is_string($value) || $value === '') {
            return null;
        }

        // A bare digit string is a unix timestamp; anything else is a date.
        $parsed = ctype_digit($value) ? (int) $value : strtotime($value);

        return $parsed === false ? null : gmdate('Y-m-d H:i:s', $parsed);
    }

    private static function normaliseReason(mixed $reason): ?string
    {
        if ($reason instanceof \Stringable) {
            $reason = (string) $reason;
        }

        if (! is_string($reason) || $reason === '') {
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
            ->where('expires_at', '<', gmdate('Y-m-d H:i:s', $before ?? time()))
            ->delete();
    }
}
