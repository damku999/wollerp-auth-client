<?php

declare(strict_types=1);

/**
 * CONTRACT §2: "The algorithm is pinned by the verifier, never read from the
 * token." `alg: none` is the oldest JWT bypass in existence — a verifier that
 * honours the header simply skips signature verification entirely.
 */
it('rejects alg:none with an empty signature', function (): void {
    $token = $this->tokens->algNone($this->tokens->payload());

    $exception = rejects(fn () => $this->validator()->validate($token));

    expect($exception->reason())->toBe('token_algorithm_not_allowed')
        ->and($exception->status())->toBe(401);
});

it('rejects alg:none carrying a junk signature', function (): void {
    $token = $this->tokens->algNone($this->tokens->payload(), 'bm90LWEtc2lnbmF0dXJl');

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_algorithm_not_allowed');
});

it('rejects the capitalisation variants of none', function (string $variant): void {
    $token = $this->tokens->hs256WithPublicKey($this->tokens->payload(), $variant);

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_algorithm_not_allowed');
})->with(['None', 'NONE', 'nOnE', 'none ']);

it('rejects a token with no alg in the header at all', function (): void {
    $token = $this->tokens->sign($this->tokens->payload());

    // Re-encode the header without `alg`, keeping the real RS256 signature.
    [$header, $body, $signature] = explode('.', $token);
    $stripped = rtrim(strtr(base64_encode(json_encode(['typ' => 'JWT', 'kid' => $this->tokens->kid])), '+/', '-_'), '=');

    expect(rejects(fn () => $this->validator()->validate("{$stripped}.{$body}.{$signature}"))->reason())
        ->toBe('token_algorithm_not_allowed');
});
