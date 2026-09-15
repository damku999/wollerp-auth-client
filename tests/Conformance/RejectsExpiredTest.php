<?php

declare(strict_types=1);

/**
 * CONTRACT §1: access tokens live 15 minutes. That TTL is the backstop for the
 * whole revocation design (§6) — if expiry does not actually bite, a dropped
 * revocation webhook means a session that never ends.
 */
it('rejects a token past exp', function (): void {
    $token = $this->tokens->sign($this->tokens->payload([
        'iat' => time() - 3600,
        'nbf' => time() - 3600,
        'exp' => time() - 1800,
    ]));

    $exception = rejects(fn () => $this->validator()->validate($token));

    expect($exception->reason())->toBe('token_expired')
        ->and($exception->status())->toBe(401);
});

it('rejects a token that expired just outside the leeway window', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(['exp' => time() - 61]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_expired');
});

it('rejects a token with no exp claim', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(remove: ['exp']));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_claims_invalid');
});

it('rejects a token that is not yet valid', function (): void {
    $token = $this->tokens->sign($this->tokens->payload([
        'nbf' => time() + 3600,
        'iat' => time() + 3600,
        'exp' => time() + 7200,
    ]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_not_yet_valid');
});

it('rejects a token issued in the future', function (): void {
    $token = $this->tokens->sign($this->tokens->payload([
        'iat' => time() + 3600,
        'exp' => time() + 7200,
    ], remove: ['nbf']));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_not_yet_valid');
});

it('rejects an expired token through the full request pipeline', function (): void {
    $request = $this->requestWithToken(
        $this->tokens->sign($this->tokens->payload(['exp' => time() - 1800]))
    );

    expect(rejects(fn () => $this->guard()->authenticateRequest($request))->reason())
        ->toBe('token_expired');
});
