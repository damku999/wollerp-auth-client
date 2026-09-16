<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Wollerp\AuthClient\Conformance\CheckResult;
use Wollerp\AuthClient\Conformance\ConformanceSuite;
use Wollerp\AuthClient\Conformance\Report;
use Wollerp\AuthClient\Token\TokenValidator;

/**
 * The suite that ships to consumers, tested here.
 *
 * INTEGRATION.md §8 check 1 is the gate a product passes before it validates
 * real tokens for real users, so it is not enough that it exists — it has to be
 * green when the wiring is right, RED when it is wrong, and impossible to
 * quietly shrink. That last property is the whole point: everything this suite
 * catches is also something somebody could be tempted to delete at 2am when it
 * goes red during a release.
 */
it('passes against a correctly wired application', function (): void {
    $report = $this->conformance()->run();

    expect($report->passed())->toBeTrue($report->failureSummary())
        ->and($report->failures())->toBe([]);
});

it('is not vacuously green — every bypass guard ran and passed', function (): void {
    $status = [];

    foreach ($this->conformance()->run()->results as $result) {
        $status[$result->id] = $result->status;
    }

    // A suite that skipped or silently dropped everything would also report
    // zero failures. These are the ones that must have actually executed.
    foreach (ConformanceSuite::BYPASS_GUARDS as $id) {
        expect($status[$id] ?? '(absent)')->toBe(
            CheckResult::PASS,
            "{$id} guards a complete authentication bypass and did not run and pass."
        );
    }
});

it('makes no network calls, so it is safe on a production host', function (): void {
    $before = count(Http::recorded());

    $this->conformance()->run();

    // The harness stubs only the JWKS URL and Http::preventStrayRequests() is
    // on, so anything escaping the suite's own offline client would either be
    // recorded here or blow up.
    expect(count(Http::recorded()))->toBe($before);
});

it('never touches the real JWKS cache', function (): void {
    // Warm the consumer's real cache, then run the suite, then prove the real
    // validator still resolves the real key. Leaking an ephemeral conformance
    // key into the live cache under any kid would be a genuine incident.
    $this->validator()->validate($this->tokens->sign($this->tokens->payload()));

    $this->conformance()->run();

    expect($this->validator()->validate($this->tokens->sign($this->tokens->payload()))->uid())
        ->toBe(4217);
});

/**
 * ── The anti-thinning gate ───────────────────────────────────────────────────
 */
it('executes exactly the checks its manifest declares', function (): void {
    $report = $this->conformance()->run();

    expect($report->executedIds())
        ->toBe([...array_column(ConformanceSuite::CHECKS, 'id'), 'suite.integrity']);
});

it('reports its own integrity as a check, so a thinned manifest fails the run', function (): void {
    $integrity = array_values(array_filter(
        $this->conformance()->run()->results,
        fn (CheckResult $result): bool => $result->id === 'suite.integrity',
    ));

    expect($integrity)->toHaveCount(1)
        ->and($integrity[0]->status)->toBe(CheckResult::PASS)
        ->and($integrity[0]->severity)->toBe(CheckResult::PIN);
});

it('still declares every check that guards a complete bypass', function (string $id): void {
    expect(array_column(ConformanceSuite::CHECKS, 'id'))->toContain($id);
})->with(ConformanceSuite::BYPASS_GUARDS);

it('has a manifest entry for every check method, and a method for every entry', function (): void {
    $methods = array_column(ConformanceSuite::CHECKS, 'method');

    foreach ($methods as $method) {
        expect(method_exists(ConformanceSuite::class, $method))->toBeTrue(
            "The manifest declares {$method}() but no such method exists."
        );
    }

    expect($methods)->toHaveCount(count(array_unique($methods)));
});

it('declares no duplicate check ids', function (): void {
    $ids = array_column(ConformanceSuite::CHECKS, 'id');

    expect($ids)->toHaveCount(count(array_unique($ids)));
});

it('keeps every pin check fatal, with no way to downgrade one', function (): void {
    $severities = array_unique(array_column(ConformanceSuite::CHECKS, 'severity'));

    expect($severities)->each->toBeIn([CheckResult::PIN, CheckResult::POSTURE]);

    foreach (ConformanceSuite::CHECKS as $check) {
        if (! str_starts_with($check['id'], 'posture.')) {
            expect($check['severity'])->toBe(
                CheckResult::PIN,
                "{$check['id']} is not a posture check and must be fatal."
            );
        }
    }
});

it('gives every check a reason it exists, not just a name', function (): void {
    foreach (ConformanceSuite::CHECKS as $check) {
        expect(trim($check['guards']))->not->toBe('', "{$check['id']} has no `guards` rationale.")
            ->and(strlen($check['guards']))->toBeGreaterThan(40);
    }
});

/**
 * ── It has to go red for the right reasons ───────────────────────────────────
 *
 * Each of these breaks one thing in the consumer's configuration and asserts
 * the suite names that thing. A gate nobody has watched fail is not a gate.
 */
it('fails when the product has no audience slug', function (): void {
    config()->set('wollerp-auth.audience', '');

    $report = $this->conformance()->run();

    expect($report->passed())->toBeFalse()
        ->and(failedIds($report))->toContain('wiring.config.audience_configured');
});

it('fails when the audience slug carries stray whitespace', function (): void {
    config()->set('wollerp-auth.audience', 'cc ');

    expect(failedIds($this->conformance()->run()))->toContain('wiring.config.audience_configured');
});

it('fails when the guard driver is not the Wollerp one', function (): void {
    config()->set('auth.guards.wollerp', ['driver' => 'session', 'provider' => 'users']);

    expect(failedIds($this->conformance()->run()))->toContain('wiring.guard.driver_resolves');
});

it('fails when a middleware alias has been shadowed', function (): void {
    $this->app->make('router')->aliasMiddleware('wollerp.auth', Closure::class);

    expect(failedIds($this->conformance()->run()))->toContain('wiring.middleware.aliases_registered');
});

it('fails when the denylist table is missing from the configured connection', function (): void {
    $this->app->make('db')->connection()->statement('DROP TABLE revoked_tokens');

    expect(failedIds($this->conformance()->run()))->toContain('wiring.denylist.revocation_bites');
});

it('fails when bundled keys are configured but unusable', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', [
        ['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => 'typo', 'n' => 'AA', 'e' => 'AQAB'],
    ]);

    $report = $this->conformance()->run();

    expect($report->passed())->toBeFalse()
        ->and(failedIds($report))->toContain('wiring.jwks.bundled_keys_usable');
});

/**
 * ── Posture warns, and --strict makes it bite ────────────────────────────────
 */
it('warns rather than fails on an empty bundled-key set', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', []);

    $report = $this->conformance()->run();

    expect($report->passed())->toBeTrue()
        ->and(array_map(
            fn (CheckResult $r): string => $r->id,
            $report->warnings(),
        ))->toContain('posture.jwks.bundled_keys_present');
});

it('turns that warning into a failure under strict', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', []);

    $report = $this->conformance()->run(strict: true);

    expect($report->passed())->toBeFalse()
        ->and(failedIds($report))->toContain('posture.jwks.bundled_keys_present');
});

it('stops warning once bundled keys are populated', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', [$this->tokens->jwk()]);

    $report = $this->conformance()->run(strict: true);

    expect($report->passed())->toBeTrue($report->failureSummary());
});

/**
 * ── It reads the consumer's real config, not its own defaults ────────────────
 */
it('tests against the leeway the consumer actually configured', function (): void {
    config()->set('wollerp-auth.token.leeway', 0);

    $report = $this->conformance()->run();

    expect($report->passed())->toBeTrue($report->failureSummary())
        ->and(detailFor($report, 'pin.temporal.accepted_inside_leeway'))
        ->toContain('Leeway is 0 and honoured exactly');
});

it('reports a clamped leeway rather than accepting it', function (): void {
    config()->set('wollerp-auth.token.leeway', 86400);

    $report = $this->conformance()->run();

    expect($report->passed())->toBeTrue($report->failureSummary())
        ->and(detailFor($report, 'pin.temporal.leeway_capped'))
        ->toContain('clamped to '.TokenValidator::MAX_LEEWAY);
});

it('carries the live issuer and audience on the report', function (): void {
    $report = $this->conformance()->run();

    expect($report->issuer)->toBe('https://auth.wollerp.lumicorelabs.com')
        ->and($report->audience)->toBe('cc');
});

/**
 * @return list<string>
 */
function failedIds(Report $report): array
{
    return array_map(fn (CheckResult $result): string => $result->id, $report->failures());
}

function detailFor(Report $report, string $id): string
{
    foreach ($report->results as $result) {
        if ($result->id === $id) {
            return $result->detail;
        }
    }

    return '';
}
