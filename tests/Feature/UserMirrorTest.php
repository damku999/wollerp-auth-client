<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Wollerp\AuthClient\Exceptions\MirrorWriteForbiddenException;
use Wollerp\AuthClient\Mirror\MirroredUser;
use Wollerp\AuthClient\Mirror\MirrorSynchroniser;
use Wollerp\AuthClient\Tests\Support\TokenFactory;
use Wollerp\AuthClient\Token\Claims;

/**
 * CONTRACT §4.
 */
function authenticateWith(array $overrides = []): Claims
{
    /** @var \Wollerp\AuthClient\Tests\TestCase $test */
    $test = test();

    return $test->guard()->authenticateRequest(
        $test->requestWithToken($test->tokens->sign($test->tokens->payload($overrides)))
    );
}

it('has no password column, and never will', function (): void {
    expect(Schema::hasTable('users_mirror'))->toBeTrue()
        ->and(Schema::hasColumn('users_mirror', 'password'))->toBeFalse()
        ->and(Schema::hasColumn('users_mirror', 'remember_token'))->toBeFalse();
});

it('has every column the contract specifies', function (string $column): void {
    expect(Schema::hasColumn('users_mirror', $column))->toBeTrue();
})->with([
    'auth_user_id', 'auth_user_uuid', 'name', 'email',
    'status', 'email_verified_at', 'version', 'synced_at',
]);

it('creates the mirror row from the token on first sight of a user', function (): void {
    authenticateWith();

    $row = DB::table('users_mirror')->where('auth_user_id', TokenFactory::UID)->first();

    expect($row)->not->toBeNull()
        ->and($row->auth_user_uuid)->toBe(TokenFactory::SUB)
        ->and($row->email)->toBe('user@example.com')
        ->and($row->name)->toBe('Jane Smith')
        ->and((int) $row->version)->toBe(7);
});

it('does not write when ver has not drifted', function (): void {
    authenticateWith();

    expect($this->mirror()->syncFromClaims($this->validator()->validate(
        $this->tokens->sign($this->tokens->payload())
    )))->toBeFalse();
});

it('upserts when ver drifts upward', function (): void {
    authenticateWith();
    authenticateWith(['ver' => 8, 'name' => 'Jane Smith-Jones']);

    $row = DB::table('users_mirror')->where('auth_user_id', TokenFactory::UID)->first();

    expect((int) $row->version)->toBe(8)
        ->and($row->name)->toBe('Jane Smith-Jones');
});

it('never rolls the mirror backwards on a stale token', function (): void {
    authenticateWith(['ver' => 9, 'name' => 'Current Name']);
    authenticateWith(['ver' => 3, 'name' => 'Stale Name']);

    $row = DB::table('users_mirror')->where('auth_user_id', TokenFactory::UID)->first();

    expect((int) $row->version)->toBe(9)
        ->and($row->name)->toBe('Current Name');
});

it('leaves status alone on a token-driven upsert, because the token does not carry it', function (): void {
    authenticateWith();

    $this->mirror()->syncFromRecord([
        'id' => TokenFactory::UID,
        'uuid' => TokenFactory::SUB,
        'name' => 'Jane Smith',
        'email' => 'user@example.com',
        'status' => 'suspended',
        'version' => 8,
    ]);

    authenticateWith(['ver' => 9]);

    $row = DB::table('users_mirror')->where('auth_user_id', TokenFactory::UID)->first();

    expect($row->status)->toBe('suspended')
        ->and((int) $row->version)->toBe(9);
});

it('preserves the original email verification time across version bumps', function (): void {
    authenticateWith();

    $first = DB::table('users_mirror')->where('auth_user_id', TokenFactory::UID)->value('email_verified_at');

    authenticateWith(['ver' => 12]);

    expect(DB::table('users_mirror')->where('auth_user_id', TokenFactory::UID)->value('email_verified_at'))
        ->toBe($first);
});

it('clears the verification timestamp when the token says the email is no longer verified', function (): void {
    authenticateWith();
    authenticateWith(['ver' => 8, 'email_verified' => false]);

    expect(DB::table('users_mirror')->where('auth_user_id', TokenFactory::UID)->value('email_verified_at'))
        ->toBeNull();
});

it('refuses a write that did not come from the synchroniser', function (): void {
    authenticateWith();

    $user = MirroredUser::query()->find(TokenFactory::UID);

    expect(fn () => $user->update(['email' => 'attacker@example.com']))
        ->toThrow(MirrorWriteForbiddenException::class);

    expect(DB::table('users_mirror')->where('auth_user_id', TokenFactory::UID)->value('email'))
        ->toBe('user@example.com');
});

it('refuses a create that did not come from the synchroniser', function (): void {
    expect(fn () => MirroredUser::query()->create([
        'auth_user_id' => 99,
        'auth_user_uuid' => '01JFAKE00000000000000000AA',
        'version' => 1,
    ]))->toThrow(MirrorWriteForbiddenException::class);
});

it('refuses a delete that did not come from the synchroniser', function (): void {
    authenticateWith();

    $user = MirroredUser::query()->find(TokenFactory::UID);

    expect(fn () => $user->delete())->toThrow(MirrorWriteForbiddenException::class);
});

it('keeps the write gate shut outside a synchroniser call', function (): void {
    expect(MirrorSynchroniser::isSynchronising())->toBeFalse();

    authenticateWith();

    expect(MirrorSynchroniser::isSynchronising())->toBeFalse();
});

it('cannot be bypassed with the quiet write helpers', function (): void {
    authenticateWith();

    $user = MirroredUser::query()->find(TokenFactory::UID);
    $user->email = 'attacker@example.com';

    expect(fn () => $user->saveQuietly())->toThrow(MirrorWriteForbiddenException::class)
        ->and(fn () => $user->deleteQuietly())->toThrow(MirrorWriteForbiddenException::class);

    expect(DB::table('users_mirror')->where('auth_user_id', TokenFactory::UID)->value('email'))
        ->toBe('user@example.com');
});

it('exposes the mirrored user through auth()->user() with no credential surface', function (): void {
    authenticateWith();

    $user = $this->guard()->user();

    expect($user)->toBeInstanceOf(MirroredUser::class)
        ->and($user->getAuthIdentifier())->toBe(TokenFactory::UID)
        ->and($user->getAuthPassword())->toBe('')
        ->and($user->getRememberToken())->toBe('');
});
