<?php

declare(strict_types=1);

namespace Wollerp\AuthClient;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Wollerp\AuthClient\Console\SyncUsersCommand;
use Wollerp\AuthClient\Guard\TokenGuard;
use Wollerp\AuthClient\Hmac\Signer;
use Wollerp\AuthClient\Hmac\Verifier;
use Wollerp\AuthClient\Http\Middleware\Authenticate;
use Wollerp\AuthClient\Http\Middleware\VerifyHmacSignature;
use Wollerp\AuthClient\Jwks\JwksCache;
use Wollerp\AuthClient\Jwks\JwksClient;
use Wollerp\AuthClient\Mirror\MirroredUser;
use Wollerp\AuthClient\Mirror\MirrorSynchroniser;
use Wollerp\AuthClient\Revocation\DenylistChecker;
use Wollerp\AuthClient\Token\TokenValidator;

final class WollerpAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/wollerp-auth.php', 'wollerp-auth');

        // Done in register(), not boot(): any model instantiated before boot
        // completes must already know its connection and table.
        MirroredUser::configureStorage(
            $this->config('database.connection'),
            (string) $this->config('database.mirror_table', 'users_mirror'),
        );

        $this->registerJwks();
        $this->registerTokenValidation();
        $this->registerMirror();
        $this->registerServicePlane();
        $this->registerMiddleware();
        $this->registerCommand();
    }

    public function boot(): void
    {
        $this->registerGuardDriver();
        $this->registerMiddlewareAliases();
        $this->registerPublishing();
    }

    private function registerJwks(): void
    {
        $this->app->singleton(JwksCache::class, function (Application $app): JwksCache {
            $store = (string) $this->config('jwks.cache_store', 'file');

            return new JwksCache(
                $app->make(CacheFactory::class)->store($store !== '' ? $store : null),
                (string) $this->config('jwks.cache_key', 'wollerp-auth:jwks'),
                (int) $this->config('jwks.ttl', 21600),
                (int) $this->config('jwks.refetch_cooldown', 60),
            );
        });

        $this->app->singleton(JwksClient::class, function (Application $app): JwksClient {
            $bundled = $this->config('jwks.bundled_keys', []);

            return new JwksClient(
                $app->make(HttpFactory::class),
                $app->make(JwksCache::class),
                (string) $this->config('jwks.url', ''),
                is_array($bundled) ? $bundled : [],
                (int) $this->config('jwks.http_timeout', 5),
            );
        });
    }

    private function registerTokenValidation(): void
    {
        $this->app->singleton(TokenValidator::class, function (Application $app): TokenValidator {
            return new TokenValidator(
                $app->make(JwksClient::class),
                (string) $this->config('issuer', ''),
                (string) $this->config('audience', ''),
                (int) $this->config('token.leeway', TokenValidator::DEFAULT_LEEWAY),
                (int) $this->config('token.max_length', 8192),
            );
        });

        $this->app->singleton(DenylistChecker::class, function (Application $app): DenylistChecker {
            $connection = $this->config('database.connection');

            return new DenylistChecker(
                $app->make(ConnectionResolverInterface::class)->connection(
                    is_string($connection) && $connection !== '' ? $connection : null
                ),
                (string) $this->config('database.revoked_table', 'revoked_tokens'),
            );
        });
    }

    private function registerMirror(): void
    {
        $this->app->singleton(MirrorSynchroniser::class, function (Application $app): MirrorSynchroniser {
            /** @var class-string<Model> $modelClass */
            $modelClass = (string) $this->config('mirror.model', MirroredUser::class);

            return new MirrorSynchroniser(
                $app->make($modelClass),
                (bool) $this->config('mirror.enabled', true),
            );
        });
    }

    private function registerServicePlane(): void
    {
        $this->app->singleton(Signer::class, function (): Signer {
            return new Signer(
                (string) $this->config('hmac.project', ''),
                (string) $this->config('hmac.outbound', ''),
            );
        });

        $this->app->singleton(Verifier::class, function (): Verifier {
            $secrets = $this->config('hmac.secrets', []);

            return new Verifier(
                is_array($secrets) ? array_map(strval(...), array_filter($secrets, is_string(...))) : [],
                (int) $this->config('hmac.window', Verifier::DEFAULT_WINDOW),
            );
        });
    }

    private function registerMiddleware(): void
    {
        $this->app->bind(Authenticate::class, function (Application $app): Authenticate {
            return new Authenticate(
                $app->make(AuthFactory::class),
                (string) $this->config('guard', 'wollerp'),
            );
        });

        $this->app->bind(VerifyHmacSignature::class, function (Application $app): VerifyHmacSignature {
            $allowed = $this->config('hmac.allowed_ips', []);

            return new VerifyHmacSignature(
                $app->make(Verifier::class),
                is_array($allowed) ? array_values(array_map(strval(...), $allowed)) : [],
            );
        });
    }

    private function registerCommand(): void
    {
        $this->app->singleton(SyncUsersCommand::class, function (Application $app): SyncUsersCommand {
            return new SyncUsersCommand(
                $app->make(HttpFactory::class),
                $app->make(MirrorSynchroniser::class),
                $app->make(Signer::class),
                (string) $this->config('base_url', ''),
                (string) $this->config('sync.endpoint', '/api/v1/internal/users'),
                (int) $this->config('sync.per_page', 500),
                (int) $this->config('sync.timeout', 30),
            );
        });

        if ($this->app->runningInConsole()) {
            $this->commands([SyncUsersCommand::class]);
        }
    }

    private function registerGuardDriver(): void
    {
        /** @var \Illuminate\Auth\AuthManager $auth */
        $auth = $this->app->make('auth');

        $auth->extend('wollerp', function (Application $app): TokenGuard {
            $guard = new TokenGuard(
                $app->make(TokenValidator::class),
                $app->make(DenylistChecker::class),
                $app->make(MirrorSynchroniser::class),
                $app->make('request'),
            );

            // Guards are resolved once per request lifecycle but the container's
            // request instance is rebound (octane, sub-requests, tests). Keep the
            // guard pointed at the live one.
            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    private function registerMiddlewareAliases(): void
    {
        if (! $this->app->bound('router')) {
            return;
        }

        /** @var Router $router */
        $router = $this->app->make('router');

        $router->aliasMiddleware('wollerp.auth', Authenticate::class);
        $router->aliasMiddleware('wollerp.hmac', VerifyHmacSignature::class);
    }

    private function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__.'/../config/wollerp-auth.php' => $this->app->configPath('wollerp-auth.php'),
        ], 'wollerp-auth-config');

        $stubs = __DIR__.'/../database/migrations';
        $timestamp = date('Y_m_d_His');

        $this->publishes([
            $stubs.'/create_users_mirror_table.php.stub' => $this->app->databasePath(
                "migrations/{$timestamp}_create_users_mirror_table.php"
            ),
            $stubs.'/create_revoked_tokens_table.php.stub' => $this->app->databasePath(
                'migrations/'.date('Y_m_d_His', time() + 1).'_create_revoked_tokens_table.php'
            ),
        ], 'wollerp-auth-migrations');
    }

    private function config(string $key, mixed $default = null): mixed
    {
        return $this->app->make(ConfigRepository::class)->get("wollerp-auth.{$key}", $default);
    }
}
