<?php

declare(strict_types=1);

use Illuminate\Config\Repository;
use Wollerp\AuthClient\Exceptions\UnconfiguredIdentityException;
use Wollerp\AuthClient\Exceptions\WollerpAuthException;
use Wollerp\AuthClient\Support\PlatformIdentity;
use Wollerp\AuthClient\WollerpAuthServiceProvider;

/**
 * `WOLLERP_SERVICE_SLUG` already fails closed — TokenValidator refuses to
 * construct without it. The gap this covers is *when*: the validator is a lazy
 * singleton, so a deploy missing the variable boots cleanly, answers `/up` with
 * a 200, passes a smoke test, and then fails for every real user.
 *
 * Every product was writing this assertion for itself.
 */
function bootProviderAs(string $argv1): void
{
    $previous = $_SERVER['argv'][1] ?? null;
    $_SERVER['argv'][1] = $argv1;

    try {
        (new WollerpAuthServiceProvider(app()))->boot();
    } finally {
        if ($previous === null) {
            unset($_SERVER['argv'][1]);
        } else {
            $_SERVER['argv'][1] = $previous;
        }
    }
}

it('refuses to finish booting without a service slug', function (): void {
    config()->set('wollerp-auth.audience', '');

    expect(fn () => bootProviderAs('config:cache'))
        ->toThrow(UnconfiguredIdentityException::class);
});

it('refuses to finish booting without an issuer', function (): void {
    config()->set('wollerp-auth.issuer', '');

    expect(fn () => bootProviderAs('config:cache'))
        ->toThrow(UnconfiguredIdentityException::class);
});

it('names the environment variable a human has to set', function (): void {
    config()->set('wollerp-auth.audience', '   ');

    try {
        bootProviderAs('optimize');
        $this->fail('The provider booted with a blank slug.');
    } catch (UnconfiguredIdentityException $exception) {
        expect($exception->getMessage())
            ->toContain('WOLLERP_SERVICE_SLUG')
            ->toContain('config:clear');
    }
});

it('is not a WollerpAuthException, so no product maps it onto a 401', function (): void {
    // A 401 here would send every user back through login for a missing line in
    // a .env — the same mistake the package refuses to make for a JWKS outage.
    expect(is_subclass_of(
        UnconfiguredIdentityException::class,
        WollerpAuthException::class
    ))->toBeFalse();
});

it('still lets an unconfigured product publish and migrate', function (): void {
    // The regression this guards is real and would be discovered by the next
    // product: a provider that throws in boot() takes EVERY artisan command
    // with it, including `vendor:publish --tag=wollerp-auth-config`, which is
    // the first thing a new consumer runs, and the `package:discover` that
    // `composer install` triggers.
    config()->set('wollerp-auth.audience', '');

    expect(fn () => bootProviderAs('vendor:publish'))->not->toThrow(UnconfiguredIdentityException::class);
    expect(fn () => bootProviderAs('migrate'))->not->toThrow(UnconfiguredIdentityException::class);
});

it('leaves wollerp:conformance to report the problem as a named check', function (): void {
    // An exception here would replace a report naming every unwired thing with
    // a stack trace naming one.
    config()->set('wollerp-auth.audience', '');

    expect(fn () => bootProviderAs('wollerp:conformance'))
        ->not->toThrow(UnconfiguredIdentityException::class);
});

it('can be switched off, which only moves the failure back to the first token', function (): void {
    config()->set('wollerp-auth.audience', '');
    config()->set('wollerp-auth.assert_identity_on_boot', false);

    expect(fn () => bootProviderAs('config:cache'))->not->toThrow(UnconfiguredIdentityException::class);
});

it('accepts a configured identity', function (): void {
    expect(fn () => PlatformIdentity::assertConfigured(
        new Repository(['wollerp-auth' => ['audience' => 'bc', 'issuer' => 'https://auth.example.test']])
    ))->not->toThrow(UnconfiguredIdentityException::class);
});
