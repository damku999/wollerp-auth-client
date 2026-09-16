<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Support;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Wollerp\AuthClient\Exceptions\UnconfiguredIdentityException;

/**
 * Fail at BOOT on an unconfigured platform identity, not at the first token.
 *
 * `TokenValidator` already refuses to construct without `WOLLERP_SERVICE_SLUG`
 * and `WOLLERP_AUTH_ISSUER`. CONTRACT §7 makes the product registry open, so the
 * package cannot ship a default slug: a mis-deployed Brick Case would otherwise
 * announce itself as Coms Coupler and accept Coms Coupler's tokens.
 *
 * But the validator is a lazily-resolved singleton, so that guarantee only fires
 * on the first request that carries a bearer token. A deploy whose `.env` is
 * missing the variable therefore starts cleanly, answers `/up` with a 200,
 * passes a smoke test, and then fails for **every real user**. This check moves
 * the failure to the earliest possible moment: the container does not finish
 * booting, so the health check fails too and the rollout halts on its own.
 *
 * Every product was writing this for itself. It belongs here.
 */
final class PlatformIdentity
{
    /**
     * Config key => the environment variable a human has to set.
     *
     * @var array<string, string>
     */
    public const REQUIRED = [
        'audience' => 'WOLLERP_SERVICE_SLUG',
        'issuer' => 'WOLLERP_AUTH_ISSUER',
    ];

    /**
     * Console commands that still get the assertion.
     *
     * The check cannot simply run on every `php artisan`, because the first
     * thing a new consumer runs is `vendor:publish --tag=wollerp-auth-config`,
     * and a provider that throws in `boot()` takes every artisan command with it
     * — including the ones needed to fix the problem, and including the
     * `package:discover` that `composer install` triggers. A package that cannot
     * be installed before it is configured is a package the third product pays
     * for again.
     *
     * So the console is opt-in, on exactly the two kinds of command where a
     * missing slug is the failure this class exists to catch:
     *
     *   - the cache warmers a deploy pipeline runs (`config:cache`, `optimize`),
     *     which is where a broken `.env` should stop the rollout;
     *   - long-running request servers, which are the request path.
     *
     * `wollerp:conformance` is deliberately ABSENT: it reports an unconfigured
     * slug as a named failing check, which is more useful than an exception.
     *
     * @var list<string>
     */
    public const ASSERTED_CONSOLE_COMMANDS = [
        'config:cache',
        'optimize',
        'serve',
        'octane:start',
        'queue:work',
        'queue:listen',
        'schedule:work',
    ];

    /**
     * @throws UnconfiguredIdentityException
     */
    public static function assertConfigured(ConfigRepository $config): void
    {
        foreach (self::REQUIRED as $key => $variable) {
            $value = $config->get("wollerp-auth.{$key}");

            if (is_string($value) && trim($value) !== '') {
                continue;
            }

            throw UnconfiguredIdentityException::for($key, $variable);
        }
    }
}
