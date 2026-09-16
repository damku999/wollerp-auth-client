<?php

declare(strict_types=1);

use Wollerp\AuthClient\Jwks\JwksClient;
use Wollerp\AuthClient\Support\BundledKeys;
use Wollerp\AuthClient\Token\TokenValidator;

/**
 * `jwks.bundled_keys` is the cold-start fallback: the only thing standing
 * between a JWKS outage and a total auth outage on a host whose cache is empty.
 * It shipped empty with no documented way to populate it other than hand-editing
 * a published config file, which meant in practice it stayed empty.
 *
 * The parser must fail CLOSED and must never throw: it runs inside a config
 * file, and a config file that throws takes every `php artisan` command with it
 * — the same failure class as the Signer constructor defect.
 */
it('parses a full JWKS document', function (): void {
    $keys = BundledKeys::fromEnv(json_encode(['keys' => [jwk('a'), jwk('b')]]));

    expect($keys)->toHaveCount(2)
        ->and(array_column($keys, 'kid'))->toBe(['a', 'b']);
});

it('parses a bare list of JWKs', function (): void {
    expect(BundledKeys::fromEnv(json_encode([jwk('a')])))->toHaveCount(1);
});

it('parses a single JWK object', function (): void {
    expect(BundledKeys::fromEnv(json_encode(jwk('solo'))))->toHaveCount(1);
});

it('parses base64, which is the only sane way through a .env file', function (string $document): void {
    expect(BundledKeys::fromEnv(base64_encode($document)))->toHaveCount(1);
})->with([
    'jwks document' => fn () => json_encode(['keys' => [jwk('a')]]),
    'bare list' => fn () => json_encode([jwk('a')]),
    'single jwk' => fn () => json_encode(jwk('a')),
]);

it('tolerates surrounding whitespace from a copy-paste', function (): void {
    expect(BundledKeys::fromEnv("  \n".json_encode(['keys' => [jwk('a')]])."\n  "))->toHaveCount(1);
});

it('accepts an array that was already parsed', function (): void {
    expect(BundledKeys::fromEnv([jwk('a')]))->toHaveCount(1);
});

/**
 * Every one of these is a plausible .env mistake. All of them degrade to the
 * shipped default — an empty list, hence a 503 on a cold-cache outage — rather
 * than to an exception at config-load time.
 */
it('fails closed and silently on anything it cannot read', function (mixed $value): void {
    expect(BundledKeys::fromEnv($value))->toBe([]);
})->with([
    'unset' => null,
    'empty' => '',
    'whitespace' => "  \n ",
    'not json' => 'hunter2',
    'truncated json' => '{"keys": [{"kty": "RSA"',
    'quoted nonsense' => '"just a string"',
    'a number' => 42,
    'a bool' => true,
    'base64 of nothing' => 'ZW1wdHk=',
    'json null' => 'null',
    'empty document' => '{"keys": []}',
    'list of scalars' => '["a", "b"]',
]);

it('drops non-object entries but keeps the good ones beside them', function (): void {
    $keys = BundledKeys::fromEnv(json_encode(['keys' => [jwk('good'), 'nonsense', [], ['a', 'b']]]));

    expect($keys)->toHaveCount(1)
        ->and($keys[0]['kid'])->toBe('good');
});

/**
 * The property that matters: a bundled key still has to be a real key.
 */
it('does not let a bundled key bypass signature verification', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', BundledKeys::fromEnv(
        json_encode(['keys' => [$this->tokens->jwk()]])
    ));
    $this->app->forgetInstance(JwksClient::class);
    $this->app->forgetInstance(TokenValidator::class);

    $this->breakJwksEndpoint();

    // The genuine token verifies against the bundled key…
    expect($this->validator()->validate($this->tokens->sign($this->tokens->payload()))->uid())
        ->toBe(4217);

    // …and a forgery still does not, bundled fallback or no bundled fallback.
    expect(rejects(fn () => $this->validator()->validate(
        $this->tokens->hs256WithPublicKey($this->tokens->payload())
    ))->reason())->toBe('token_algorithm_not_allowed');

    expect(rejects(fn () => $this->validator()->validate(
        $this->tokens->tamperSignature($this->tokens->sign($this->tokens->payload()))
    ))->reason())->toBe('token_signature_invalid');
});

it('survives a cold-cache JWKS outage once the bundle is populated from env', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', BundledKeys::fromEnv(
        base64_encode((string) json_encode(['keys' => [$this->tokens->jwk()]]))
    ));
    $this->app->forgetInstance(JwksClient::class);
    $this->app->forgetInstance(TokenValidator::class);

    $this->breakJwksEndpoint();

    expect($this->validator()->validate($this->tokens->sign($this->tokens->payload()))->uid())
        ->toBe(4217);
});

/**
 * @return array<string, string>
 */
function jwk(string $kid): array
{
    return [
        'kty' => 'RSA',
        'use' => 'sig',
        'alg' => 'RS256',
        'kid' => $kid,
        'n' => 'AA',
        'e' => 'AQAB',
    ];
}
