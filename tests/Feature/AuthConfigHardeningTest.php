<?php

declare(strict_types=1);

use Illuminate\Config\Repository;
use Wollerp\AuthClient\Support\AuthConfigHardener;

/**
 * Laravel 11+ recursively merges its own shipped `config/auth.php` into the
 * application's, so a product that deleted `App\Models\User` and reduced
 * `config/auth.php` to one `wollerp` guard still resolves a session guard, an
 * eloquent provider pointing at the deleted class, and a password-reset broker.
 *
 * None of that appears in `config/auth.php`, which is the reason this needs a
 * test rather than a convention: the thing being removed is invisible in the
 * file a reviewer reads.
 *
 * The two directions matter equally. Removing too little leaves the surface the
 * product thought it had deleted; removing too much would break Coms Coupler,
 * which keeps `web`, `api` (Passport) and `providers.users` on purpose for its
 * whole soak period because dual-accept is its rollback.
 */
function authConfig(array $auth): Repository
{
    return new Repository(['auth' => $auth]);
}

/**
 * Laravel's shipped defaults, as the merge leaves them on a product that
 * defined only the `wollerp` guard and deleted its User model.
 */
function mergedFrameworkDefaults(): array
{
    return [
        'defaults' => ['guard' => 'wollerp', 'passwords' => 'users'],
        'guards' => [
            'wollerp' => ['driver' => 'wollerp'],
            'web' => ['driver' => 'session', 'provider' => 'users'],
        ],
        'providers' => [
            'users' => ['driver' => 'eloquent', 'model' => 'App\\Models\\ThisClassDoesNotExist'],
        ],
        'passwords' => [
            'users' => ['provider' => 'users', 'table' => 'password_reset_tokens', 'expire' => 60],
        ],
    ];
}

it('removes an eloquent provider whose model class does not exist', function (): void {
    $config = authConfig(mergedFrameworkDefaults());

    AuthConfigHardener::prune($config);

    expect($config->get('auth.providers'))->toBe([]);
});

it('removes the session guard left dangling by that provider', function (): void {
    $config = authConfig(mergedFrameworkDefaults());

    AuthConfigHardener::prune($config);

    expect($config->get('auth.guards'))->toBe(['wollerp' => ['driver' => 'wollerp']]);
});

it('removes the password broker, so a product with no passwords ships with none', function (): void {
    // CONTRACT §4 — the product database must not be capable of authenticating
    // anyone. A configured reset broker over a table that does not exist is the
    // opposite of that claim, sitting where nobody reads it.
    $config = authConfig(mergedFrameworkDefaults());

    AuthConfigHardener::prune($config);

    expect($config->get('auth.passwords'))->toBe([])
        ->and($config->get('auth.defaults.passwords'))->toBeNull();
});

it('reports exactly what it removed, because config/auth.php cannot show it', function (): void {
    $config = authConfig(mergedFrameworkDefaults());

    $removed = AuthConfigHardener::prune($config);

    expect($removed)->toBe([
        'auth.providers.users',
        'auth.guards.web',
        'auth.passwords.users',
        'auth.defaults.passwords',
    ])->and($config->get(AuthConfigHardener::RECORD_KEY))->toBe($removed);
});

it('leaves the default guard alone, because repointing it is the product\'s decision', function (): void {
    $auth = mergedFrameworkDefaults();
    $auth['defaults']['guard'] = 'web';

    $config = authConfig($auth);

    AuthConfigHardener::prune($config);

    expect($config->get('auth.defaults.guard'))->toBe('web');
});

it('is a no-op on a product that still has a User model', function (): void {
    // Coms Coupler through its whole soak period. Its `web` + `api` + `users`
    // entries are deliberate, and dual-accept IS its rollback — removing any of
    // them would turn a one-line revert into a database restore.
    $auth = [
        'defaults' => ['guard' => 'web', 'passwords' => 'users'],
        'guards' => [
            'web' => ['driver' => 'session', 'provider' => 'users'],
            'api' => ['driver' => 'passport', 'provider' => 'users'],
            'wollerp' => ['driver' => 'wollerp'],
        ],
        'providers' => [
            'users' => ['driver' => 'eloquent', 'model' => Repository::class],
        ],
        'passwords' => [
            'users' => ['provider' => 'users', 'table' => 'password_reset_tokens'],
        ],
    ];

    $config = authConfig($auth);

    expect(AuthConfigHardener::prune($config))->toBe([])
        ->and($config->get('auth'))->toBe($auth);
});

it('never touches a database-driver provider, which it cannot verify without a query', function (): void {
    $config = authConfig([
        'guards' => ['web' => ['driver' => 'session', 'provider' => 'legacy']],
        'providers' => ['legacy' => ['driver' => 'database', 'table' => 'users']],
    ]);

    expect(AuthConfigHardener::prune($config))->toBe([])
        ->and($config->get('auth.providers'))->toHaveKey('legacy');
});

it('leaves the wollerp guard alone, because it declares no provider', function (): void {
    $config = authConfig(mergedFrameworkDefaults());

    AuthConfigHardener::prune($config);

    expect($config->get('auth.guards.wollerp'))->toBe(['driver' => 'wollerp']);
});

it('runs from the service provider and records the result on the live app', function (): void {
    // Wiring check. The harness's auth config is healthy — Testbench's provider
    // points at Illuminate\Foundation\Auth\User, which exists — so the correct
    // outcome here is an empty removal list, not a missing one. A null would
    // mean register() never called the hardener at all.
    expect(config(AuthConfigHardener::RECORD_KEY))->toBe([])
        ->and(config('auth.guards.wollerp'))->toBe(['driver' => 'wollerp']);
});
