<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Wollerp\AuthClient\Hmac\Signer;
use Wollerp\AuthClient\Tests\Support\TokenFactory;

/**
 * CONTRACT §4 layer 3 over the §5 service plane.
 *
 * The response shape is no longer an assumption: CONTRACT §5.4 pins it as
 * `{ data: [...], next_cursor, has_more }`, with per-record field names that ARE
 * the users_mirror column names — `auth_user_id`, `auth_user_uuid`, `name`,
 * `email`, `status`, `email_verified_at`, `version`. That is what
 * App\Http\Controllers\Internal\UserSyncController actually emits, via
 * User::toMirrorProjection(). These fixtures use those names so the suite
 * exercises the real wire shape rather than only the legacy fallback.
 *
 * MirrorSynchroniser::syncFromRecord() still accepts `id`/`uuid`/`sub` as
 * fallbacks. That leniency is deliberate and it has its own test below — but it
 * must not be the ONLY thing under test, or the canonical path ships unproven.
 */
function fakeUserPage(array $users, ?string $nextCursor = null): void
{
    Http::fake([
        '*/api/v1/internal/users*' => Http::response([
            'data' => $users,
            'next_cursor' => $nextCursor,
            'has_more' => $nextCursor !== null,
        ]),
        '*' => Http::response(['keys' => [TokenFactory::shared()->jwk()]]),
    ]);
}

/**
 * One record in the exact CONTRACT §5.4 shape.
 */
function mirrorRecord(int $id, string $uuid, string $name, string $email, string $status, int $version): array
{
    return [
        'auth_user_id' => $id,
        'auth_user_uuid' => $uuid,
        'name' => $name,
        'email' => $email,
        'status' => $status,
        'email_verified_at' => '2026-01-04T09:00:00+00:00',
        'version' => $version,
    ];
}

it('backfills the mirror from the internal users endpoint', function (): void {
    fakeUserPage([
        mirrorRecord(4217, TokenFactory::SUB, 'Jane Smith', 'user@example.com', 'active', 7),
        mirrorRecord(4218, '01JBX7K2QF8N3M5P9R4T6V8W0Z', 'Sam Patel', 'sam@example.com', 'suspended', 2),
    ]);

    $this->artisan('users:sync')->assertSuccessful();

    $row = DB::table('users_mirror')->where('auth_user_id', 4218)->first();

    expect(DB::table('users_mirror')->count())->toBe(2)
        ->and($row->status)->toBe('suspended')
        ->and($row->auth_user_uuid)->toBe('01JBX7K2QF8N3M5P9R4T6V8W0Z')
        ->and($row->email)->toBe('sam@example.com')
        ->and((int) $row->version)->toBe(2);
});

it('still accepts the legacy id/uuid field names', function (): void {
    // MirrorSynchroniser's documented fallback. Kept under test so the leniency
    // is a decision rather than an accident, but it is NOT the contract shape.
    fakeUserPage([[
        'id' => 4217,
        'uuid' => TokenFactory::SUB,
        'name' => 'Jane Smith',
        'email' => 'user@example.com',
        'status' => 'active',
        'version' => 7,
    ]]);

    $this->artisan('users:sync')->assertSuccessful();

    expect(DB::table('users_mirror')->where('auth_user_id', 4217)->value('auth_user_uuid'))
        ->toBe(TokenFactory::SUB);
});

it('asks for pages with `limit`, the parameter the auth server validates', function (): void {
    // CONTRACT §5.3 spells the endpoint `?since=&cursor=&limit=`, and
    // UserSyncRequest validates `limit`. `per_page` is not rejected — it is
    // ignored — so getting this wrong silently pins every page to the server
    // default and makes --per-page a no-op.
    fakeUserPage([]);

    $this->artisan('users:sync', ['--per-page' => 250])->assertSuccessful();

    Http::assertSent(fn ($request): bool => str_contains($request->url(), 'limit=250')
        && ! str_contains($request->url(), 'per_page'));
});

it('clamps --per-page to the server maximum instead of earning a 422', function (): void {
    // §5.4 caps limit at 1000 and UserSyncRequest enforces it with `max:1000`,
    // which rejects rather than clamps.
    fakeUserPage([]);

    $this->artisan('users:sync', ['--per-page' => 5000])->assertSuccessful();

    Http::assertSent(fn ($request): bool => str_contains($request->url(), 'limit=1000'));
});

it('signs every page request per CONTRACT §5', function (): void {
    fakeUserPage([]);

    $this->artisan('users:sync', ['--since' => '2026-01-01'])->assertSuccessful();

    Http::assertSent(function ($request): bool {
        if (! str_contains($request->url(), '/api/v1/internal/users')) {
            return false;
        }

        $timestamp = $request->header(Signer::TIMESTAMP_HEADER)[0] ?? '';
        $signature = $request->header(Signer::SIGNATURE_HEADER)[0] ?? '';

        return $request->header(Signer::PROJECT_HEADER)[0] === 'cc'
            && hash_equals(
                'sha256='.hash_hmac('sha256', $timestamp.'.', 'outbound-test-secret'),
                $signature
            );
    });
});

it('passes --since through to the auth server', function (): void {
    fakeUserPage([]);

    $this->artisan('users:sync', ['--since' => '2026-01-01T00:00:00+00:00'])->assertSuccessful();

    Http::assertSent(fn ($request): bool => str_contains($request->url(), 'since='));
});

it('rejects an unparsable --since instead of silently doing a full backfill', function (): void {
    fakeUserPage([]);

    $this->artisan('users:sync', ['--since' => 'not-a-real-date'])->assertFailed();
});

it('does not write in a dry run', function (): void {
    fakeUserPage([
        mirrorRecord(4217, TokenFactory::SUB, 'Jane Smith', 'user@example.com', 'active', 7),
    ]);

    $this->artisan('users:sync', ['--dry-run' => true])->assertSuccessful();

    expect(DB::table('users_mirror')->count())->toBe(0);
});

it('fails loudly when the auth server rejects the signature', function (): void {
    Http::fake(['*' => Http::response(['error' => 'invalid_service_signature'], 401)]);

    $this->artisan('users:sync')->assertFailed();
});

it('is idempotent across repeated runs', function (): void {
    fakeUserPage([
        mirrorRecord(4217, TokenFactory::SUB, 'Jane Smith', 'user@example.com', 'active', 7),
    ]);

    $this->artisan('users:sync')->assertSuccessful();
    $this->artisan('users:sync')->assertSuccessful();

    expect(DB::table('users_mirror')->count())->toBe(1)
        ->and((int) DB::table('users_mirror')->where('auth_user_id', 4217)->value('version'))->toBe(7);
});
