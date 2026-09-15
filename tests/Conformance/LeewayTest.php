<?php

declare(strict_types=1);

use Wollerp\AuthClient\Token\TokenValidator;

/**
 * CONTRACT §2: "Clock leeway <= 60 s. Hosts run NTP."
 *
 * The cap is enforced in code, not just documented, because leeway is the one
 * knob an operator reaches for when a clock problem is causing 401s. Widening
 * it to an hour "temporarily" extends the life of every revoked and expired
 * token in the estate by an hour.
 */
it('accepts a token that expired within the leeway window', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(['exp' => time() - 30]));

    expect($this->validator()->validate($token)->uid())->toBe(4217);
});

it('rejects a token that expired outside the leeway window', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(['exp' => time() - 90]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_expired');
});

it('accepts a not-before within the leeway window', function (): void {
    $token = $this->tokens->sign($this->tokens->payload([
        'nbf' => time() + 30,
        'iat' => time() + 30,
    ]));

    expect($this->validator()->validate($token)->uid())->toBe(4217);
});

it('rejects a not-before outside the leeway window', function (): void {
    $token = $this->tokens->sign($this->tokens->payload([
        'nbf' => time() + 90,
        'iat' => time() + 90,
    ]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_not_yet_valid');
});

it('defaults to 60 seconds', function (): void {
    expect($this->validator()->leeway)->toBe(60);
});

it('clamps a configured leeway above the contract maximum', function (int $configured): void {
    config()->set('wollerp-auth.token.leeway', $configured);
    $this->app->forgetInstance(TokenValidator::class);

    expect($this->validator()->leeway)->toBe(TokenValidator::MAX_LEEWAY);

    $token = $this->tokens->sign($this->tokens->payload(['exp' => time() - 300]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_expired');
})->with([3600, 86400, PHP_INT_MAX]);

it('honours a leeway of zero', function (): void {
    config()->set('wollerp-auth.token.leeway', 0);
    $this->app->forgetInstance(TokenValidator::class);

    expect($this->validator()->leeway)->toBe(0);

    $token = $this->tokens->sign($this->tokens->payload(['exp' => time() - 5]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_expired');
});

it('clamps a negative leeway to zero rather than inverting the comparison', function (): void {
    config()->set('wollerp-auth.token.leeway', -600);
    $this->app->forgetInstance(TokenValidator::class);

    expect($this->validator()->leeway)->toBe(0);
});
