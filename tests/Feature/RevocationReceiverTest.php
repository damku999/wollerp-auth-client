<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Wollerp\AuthClient\Revocation\DenylistChecker;

/**
 * The receiving half of CONTRACT §6 — what `POST /api/v1/internal/revoke` does
 * once the HMAC middleware has let it through.
 *
 * These tests exist because the sender is not hypothetical. App\Jobs\
 * DispatchRevocationWebhook in wollerp-auth posts
 * `{ sid, jti, not_after, reason }` with `not_after` as an ISO-8601 STRING and
 * a `reason` this table is contractually required to keep. The documented
 * consumer handler forwards those inputs straight into revoke(), so the
 * signature has to survive exactly what the auth server sends — including the
 * six delivery retries, which must not each leave a row behind.
 */
function revokeWith(mixed $notAfter = null, ?string $reason = null): void
{
    /** @var DenylistChecker $denylist */
    $denylist = app(DenylistChecker::class);

    $denylist->revoke('01JBZ3K5M7N9P1Q3R5S7T9V1W3', null, $notAfter, $reason);
}

it('accepts the ISO-8601 not_after the auth server actually sends', function (): void {
    // The failure this guards is silent, not loud: coercing "2026-09-15T…" to
    // an int yields 2026, which stamps expires_at in January 1970, and the next
    // prune() then deletes the revocation and resurrects the session.
    revokeWith('2026-09-15T12:20:00+00:00', 'logout');

    $row = DB::table('revoked_tokens')->first();

    expect($row->expires_at)->toStartWith('2026-09-15')
        ->and($row->reason)->toBe('logout');
});

it('still accepts a unix timestamp', function (): void {
    revokeWith(1_789_000_000, 'admin_revoked');

    expect(DB::table('revoked_tokens')->value('expires_at'))
        ->toBe(date('Y-m-d H:i:s', 1_789_000_000));
});

it('accepts a DateTimeInterface', function (): void {
    revokeWith(new DateTimeImmutable('2026-09-15 12:20:00'), 'reuse_detected');

    expect(DB::table('revoked_tokens')->value('expires_at'))->toBe('2026-09-15 12:20:00');
});

it('keeps the revocation forever when not_after is unparsable', function (): void {
    // Null expires_at means prune() never removes the row. Retaining a
    // revocation too long is the safe direction to fail; dropping one is not.
    revokeWith('not-a-timestamp', 'logout');

    expect(DB::table('revoked_tokens')->count())->toBe(1)
        ->and(DB::table('revoked_tokens')->value('expires_at'))->toBeNull();
});

it('stores the reason CONTRACT §6 requires', function (): void {
    revokeWith(null, 'password_changed');

    expect(DB::table('revoked_tokens')->value('reason'))->toBe('password_changed');
});

it('truncates an over-long reason rather than losing the revocation', function (): void {
    revokeWith(null, str_repeat('x', 200));

    expect(strlen((string) DB::table('revoked_tokens')->value('reason')))->toBe(32)
        ->and(DB::table('revoked_tokens')->count())->toBe(1);
});

it('is idempotent across webhook retries', function (): void {
    // DispatchRevocationWebhook has six attempts and a backoff schedule, and its
    // own docblock asserts "the receiver's insert is keyed on sid so a duplicate
    // is a no-op". Make that true.
    revokeWith('2026-09-15T12:20:00+00:00', 'logout');
    revokeWith('2026-09-15T12:20:00+00:00', 'logout');
    revokeWith('2026-09-15T12:20:00+00:00', 'logout');

    expect(DB::table('revoked_tokens')->count())->toBe(1);
});

it('does not write a row when neither sid nor jti is named', function (): void {
    /** @var DenylistChecker $denylist */
    $denylist = app(DenylistChecker::class);

    $denylist->revoke(null, null, '2026-09-15T12:20:00+00:00', 'logout');
    $denylist->revoke('', '', '2026-09-15T12:20:00+00:00', 'logout');

    expect(DB::table('revoked_tokens')->count())->toBe(0);
});

it('revokes sid and jti independently without colliding', function (): void {
    /** @var DenylistChecker $denylist */
    $denylist = app(DenylistChecker::class);

    $denylist->revoke('01JBZ3K5M7N9P1Q3R5S7T9V1W3', null, null, 'logout');
    $denylist->revoke(null, '01JBY5M8P2Q4R6S8T0V2W4X6Y8', null, 'admin_revoked');

    expect(DB::table('revoked_tokens')->count())->toBe(2);
});

/*
|--------------------------------------------------------------------------
| Malformed payloads
|--------------------------------------------------------------------------
|
| The documented handler forwards `$request->input(...)` straight into
| revoke(), and `input()` returns whatever was in the JSON body. Under the
| platform's mandatory declare(strict_types=1) a narrower signature turns
| `{"sid": 12345}` into a TypeError — a 500 on a service-plane call, where the
| correct answer is a 422 naming the field. These pin that it cannot come back,
| in both directions: nothing throws, and nothing bogus gets stored.
|
*/

it('does not throw on a numeric sid, it matches on it', function (): void {
    /** @var DenylistChecker $denylist */
    $denylist = app(DenylistChecker::class);

    expect($denylist->revoke(12345, null, '2026-09-15T12:20:00+00:00', 'logout'))->toBeTrue()
        ->and(DB::table('revoked_tokens')->value('sid'))->toBe('12345')
        ->and($denylist->matches('12345', null))->toBeTrue();
});

it('does not throw on a non-scalar sid or jti', function (mixed $value): void {
    /** @var DenylistChecker $denylist */
    $denylist = app(DenylistChecker::class);

    expect($denylist->revoke($value, $value, null, null))->toBeFalse()
        ->and(DB::table('revoked_tokens')->count())->toBe(0);
})->with([
    'array' => [['01JBZ3K5M7N9P1Q3R5S7T9V1W3']],
    'object' => [(object) ['sid' => '01JBZ3K5M7N9P1Q3R5S7T9V1W3']],
    'bool' => [true],
    'float' => [1.5],
]);

it('reports false when the payload named nothing, so the handler can answer 422', function (): void {
    /** @var DenylistChecker $denylist */
    $denylist = app(DenylistChecker::class);

    // A 204 here would tell the auth server a revocation it never performed had
    // succeeded, and DispatchRevocationWebhook would stop retrying.
    expect($denylist->revoke(null, null, time(), 'logout'))->toBeFalse()
        ->and($denylist->revoke('01JBZ3K5M7N9P1Q3R5S7T9V1W3', null, time(), 'logout'))->toBeTrue();
});

it('does not throw on a malformed not_after or reason', function (): void {
    /** @var DenylistChecker $denylist */
    $denylist = app(DenylistChecker::class);

    expect($denylist->revoke('01JBZ3K5M7N9P1Q3R5S7T9V1W3', null, ['nope'], ['nope']))->toBeTrue();

    $row = DB::table('revoked_tokens')->first();

    // An unusable not_after means "never prune this row". Keeping a revocation
    // too long is the safe direction to fail; dropping one is not.
    expect($row->expires_at)->toBeNull()
        ->and($row->reason)->toBeNull();
});
