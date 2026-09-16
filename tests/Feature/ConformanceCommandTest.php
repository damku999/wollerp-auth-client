<?php

declare(strict_types=1);

use Illuminate\Console\Command;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Artisan;

/**
 * `php artisan wollerp:conformance` is INTEGRATION.md §8 check 1 in a form a
 * product can actually run and a pipeline can actually gate on.
 *
 * The exit code is the contract. Everything else on screen is for a human.
 */
it('is registered, so `artisan list` shows it on every consumer', function (): void {
    expect(array_keys($this->app->make(Kernel::class)->all()))
        ->toContain('wollerp:conformance');
});

it('exits 0 on a correctly wired application', function (): void {
    $this->artisan('wollerp:conformance')->assertExitCode(Command::SUCCESS);
});

it('exits 1 when the product has no audience slug', function (): void {
    config()->set('wollerp-auth.audience', '');

    $this->artisan('wollerp:conformance')
        ->expectsOutputToContain('wiring.config.audience_configured')
        ->assertExitCode(Command::FAILURE);
});

it('exits 1 under --strict while posture warnings are outstanding', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', []);

    $this->artisan('wollerp:conformance', ['--strict' => true])
        ->assertExitCode(Command::FAILURE);
});

it('exits 0 under --strict once they are addressed', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', [$this->tokens->jwk()]);

    $this->artisan('wollerp:conformance', ['--strict' => true])
        ->assertExitCode(Command::SUCCESS);
});

it('emits a machine-readable report for CI', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', [$this->tokens->jwk()]);

    $exitCode = Artisan::call('wollerp:conformance', ['--json' => true]);

    $decoded = json_decode(Artisan::output(), true);

    expect($exitCode)->toBe(Command::SUCCESS)
        ->and($decoded)->toBeArray()
        ->and($decoded['passed'])->toBeTrue()
        ->and($decoded['audience'])->toBe('cc')
        ->and($decoded['totals']['failed'])->toBe(0)
        ->and($decoded['checks'])->not->toBeEmpty();
});

it('names the bypass it is protecting when a check fails', function (): void {
    config()->set('wollerp-auth.audience', '');

    $this->artisan('wollerp:conformance')
        ->expectsOutputToContain('WOLLERP_SERVICE_SLUG')
        ->assertExitCode(Command::FAILURE);
});
