<?php

declare(strict_types=1);

use Wollerp\AuthClient\Tests\Support\TokenFactory;

/**
 * CONTRACT §1: "iss — exact-match only. Never prefix/suffix matched."
 *
 * The lookalikes below are the reason. `str_starts_with()` accepts
 * "https://auth.wollerp.lumicorelabs.com.attacker.example"; `str_contains()`
 * accepts anything with the issuer buried in a path.
 *
 * Note that all of these are signed with the REAL key, so the signature is
 * genuine — only the issuer check stands between them and acceptance.
 */
it('rejects a token from a different issuer', function (): void {
    $token = $this->tokens->sign($this->tokens->payload([
        'iss' => 'https://auth.someone-else.example',
    ]));

    $exception = rejects(fn () => $this->validator()->validate($token));

    expect($exception->reason())->toBe('token_issuer_mismatch')
        ->and($exception->status())->toBe(401);
});

it('rejects issuer lookalikes that a non-exact comparison would let through', function (string $issuer): void {
    $token = $this->tokens->sign($this->tokens->payload(['iss' => $issuer]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_issuer_mismatch');
})->with([
    'suffix' => TokenFactory::ISSUER.'.attacker.example',
    'prefix' => 'https://attacker.example/'.TokenFactory::ISSUER,
    'trailing slash' => TokenFactory::ISSUER.'/',
    'scheme downgrade' => 'http://auth.wollerp.lumicorelabs.com',
    'case change' => 'https://AUTH.wollerp.lumicorelabs.com',
    'path appended' => TokenFactory::ISSUER.'/realms/other',
    'empty' => ' ',
]);

it('rejects a token with no iss claim', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(remove: ['iss']));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_claims_invalid');
});
