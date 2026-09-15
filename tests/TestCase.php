<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Tests;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase as Orchestra;
use Wollerp\AuthClient\Guard\TokenGuard;
use Wollerp\AuthClient\Mirror\MirrorSynchroniser;
use Wollerp\AuthClient\Revocation\DenylistChecker;
use Wollerp\AuthClient\Tests\Support\TokenFactory;
use Wollerp\AuthClient\Token\TokenValidator;
use Wollerp\AuthClient\WollerpAuthServiceProvider;

abstract class TestCase extends Orchestra
{
    public TokenFactory $tokens;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tokens = TokenFactory::shared();

        $this->migratePackageTables();
        $this->publishJwks($this->tokens->jwk());
    }

    /**
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [WollerpAuthServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        /** @var Repository $config */
        $config = $app['config'];

        $config->set('database.default', 'wollerp_testing');
        $config->set('database.connections.wollerp_testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $config->set('cache.default', 'array');

        // The guard DRIVER is registered by the package; the guard itself is
        // the consumer's job. This line is exactly what a product adds.
        $config->set('auth.guards.wollerp', ['driver' => 'wollerp']);

        $config->set('wollerp-auth.issuer', TokenFactory::ISSUER);
        $config->set('wollerp-auth.audience', TokenFactory::AUDIENCE);
        $config->set('wollerp-auth.base_url', TokenFactory::ISSUER);
        $config->set('wollerp-auth.jwks.url', TokenFactory::JWKS_URL);
        $config->set('wollerp-auth.jwks.cache_store', 'array');
        $config->set('wollerp-auth.jwks.bundled_keys', []);
        $config->set('wollerp-auth.database.connection', null);
        $config->set('wollerp-auth.hmac.project', 'cc');
        $config->set('wollerp-auth.hmac.outbound', 'outbound-test-secret');
        $config->set('wollerp-auth.hmac.secrets', ['auth' => 'inbound-test-secret']);
        $config->set('wollerp-auth.hmac.allowed_ips', []);
    }

    /**
     * Runs the publishable stubs themselves, so a schema mistake in a stub
     * fails the suite rather than the consumer's first deploy.
     */
    protected function migratePackageTables(): void
    {
        foreach (['create_users_mirror_table', 'create_revoked_tokens_table'] as $stub) {
            /** @var Migration $migration */
            $migration = require __DIR__.'/../database/migrations/'.$stub.'.php.stub';

            $migration->up();
        }
    }

    /**
     * Stand up a fake JWKS endpoint holding exactly the keys given.
     *
     * @param  array<string, string>  ...$keys
     */
    public function publishJwks(array ...$keys): void
    {
        Http::preventStrayRequests();

        Http::fake([
            '*' => Http::response(['keys' => array_values($keys)], 200, [
                'Cache-Control' => 'public, max-age=21600',
            ]),
        ]);
    }

    public function breakJwksEndpoint(): void
    {
        Http::fake(['*' => Http::response('gateway timeout', 504)]);
    }

    public function validator(): TokenValidator
    {
        return $this->app->make(TokenValidator::class);
    }

    public function denylist(): DenylistChecker
    {
        return $this->app->make(DenylistChecker::class);
    }

    public function mirror(): MirrorSynchroniser
    {
        return $this->app->make(MirrorSynchroniser::class);
    }

    public function guard(): TokenGuard
    {
        $guard = $this->app->make('auth')->guard('wollerp');

        assert($guard instanceof TokenGuard);

        return $guard;
    }

    public function requestWithToken(string $token): Request
    {
        return Request::create('/api/v1/example', 'GET', server: [
            'HTTP_AUTHORIZATION' => 'Bearer '.$token,
        ]);
    }
}
