<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Tests;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
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

    /**
     * What the fake JWKS endpoint is currently serving, or null while it is
     * "down". Resolved at request time — see installJwksFake().
     *
     * @var list<array<string, string>>|null
     */
    private ?array $publishedKeys = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tokens = TokenFactory::shared();

        $this->migratePackageTables();
        $this->installJwksFake();
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
     * Registers exactly ONE stub, scoped to the JWKS URL, which resolves what
     * it serves at request time rather than at registration time.
     *
     * Both of those properties are load-bearing, because of how the HTTP fake
     * actually behaves. Illuminate\Http\Client\Factory::fake() MERGES stubs
     * (`$this->stubCallbacks->merge(...)`) and the handler takes the first one
     * that returns non-null (`->filter()->first()`). A stub therefore cannot be
     * replaced — only shadowed by one registered earlier.
     *
     * Registering `'*'` here, as this harness previously did, consequently made
     * a later Http::fake() in ANY test a silent no-op: breakJwksEndpoint() never
     * broke anything, a re-publish never rotated anything, and the users:sync
     * fixtures were served the JWKS document instead of their own page. Ten
     * tests failed and none of them were failing for the reason they claimed.
     *
     * So: match the JWKS URL and nothing else, and return null otherwise so a
     * test's own stubs still get their turn.
     */
    protected function installJwksFake(): void
    {
        Http::preventStrayRequests();

        // No return type declaration: Http::response() hands back a Guzzle
        // PromiseInterface, and "no stub matched" is expressed as null.
        Http::fake(function (ClientRequest $request) {
            if (! Str::is(TokenFactory::JWKS_URL.'*', $request->url())) {
                return null;
            }

            if ($this->publishedKeys === null) {
                return Http::response('gateway timeout', 504);
            }

            return Http::response(['keys' => $this->publishedKeys], 200, [
                'Cache-Control' => 'public, max-age=21600',
            ]);
        });
    }

    /**
     * Serve exactly the keys given, from now on.
     *
     * @param  array<string, string>  ...$keys
     */
    public function publishJwks(array ...$keys): void
    {
        $this->publishedKeys = array_values($keys);
    }

    public function breakJwksEndpoint(): void
    {
        $this->publishedKeys = null;
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
