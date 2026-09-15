<?php

declare(strict_types=1);

/**
 * The algorithm-confusion attack, and the single most important test in this
 * package.
 *
 * The RSA public key is PUBLISHED at the JWKS endpoint for anyone to fetch. If
 * the verifier reads `alg` from the header and dispatches on it, an attacker
 * sets `alg: HS256`, uses the public key as the HMAC secret, and mints a valid
 * token for any `sub`, `uid` and `aud` they choose. Complete bypass, no
 * credentials needed, no exploit chain.
 *
 * The only defence is pinning: the verifier decides the algorithm, the token
 * does not get a vote.
 */
it('rejects an HS256 token whose HMAC key is the RSA public key', function (): void {
    $forged = $this->tokens->hs256WithPublicKey($this->tokens->payload());

    $exception = rejects(fn () => $this->validator()->validate($forged));

    expect($exception->reason())->toBe('token_algorithm_not_allowed')
        ->and($exception->status())->toBe(401);
});

it('rejects an HS256 forgery that escalates to another user', function (): void {
    $forged = $this->tokens->hs256WithPublicKey($this->tokens->payload([
        'sub' => '01JADMIN0000000000000000AA',
        'uid' => 1,
        'email' => 'admin@example.com',
    ]));

    expect(rejects(fn () => $this->validator()->validate($forged))->reason())
        ->toBe('token_algorithm_not_allowed');
});

it('rejects an HS256 forgery through the full request pipeline, not just the validator', function (): void {
    $request = $this->requestWithToken(
        $this->tokens->hs256WithPublicKey($this->tokens->payload())
    );

    rejects(fn () => $this->guard()->authenticateRequest($request));

    expect($this->guard()->check())->toBeFalse();
});

it('rejects every other JOSE algorithm label', function (string $algorithm): void {
    $token = $this->tokens->hs256WithPublicKey($this->tokens->payload(), $algorithm);

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_algorithm_not_allowed');
})->with(['HS256', 'HS384', 'HS512', 'RS384', 'RS512', 'PS256', 'ES256', 'rs256', 'RS256 ']);
