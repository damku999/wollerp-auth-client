<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Wollerp\AuthClient\Conformance\TokenForge;
use Wollerp\AuthClient\Jwks\JwksClient;
use Wollerp\AuthClient\Support\Base64Url;
use Wollerp\AuthClient\Tests\Support\TokenFactory;
use Wollerp\AuthClient\Token\TokenValidator;

/**
 * CONTRACT §3. The auth server publishes the current AND previous key, so a
 * rotation is never a synchronised outage. A `kid` in neither is either a
 * forgery or a key rotated out long ago; both are 401.
 *
 * The other half of this file is the availability half: a JWKS outage must not
 * become an auth outage for keys we already hold.
 */
it('rejects a token whose kid is published nowhere', function (): void {
    $impostor = new TokenFactory('never-published');

    $exception = rejects(
        fn () => $this->validator()->validate($impostor->sign($impostor->payload()))
    );

    expect($exception->reason())->toBe('token_signing_key_unknown')
        ->and($exception->status())->toBe(401);
});

it('picks up a rotated-in key on the forced refetch', function (): void {
    $rotated = new TokenFactory('2026-12');
    $token = $rotated->sign($rotated->payload());

    // Warm the cache with only the old key, then rotate at the endpoint.
    $this->validator()->validate($this->tokens->sign($this->tokens->payload()));
    $this->publishJwks($rotated->jwk(), $this->tokens->jwk());

    expect($this->validator()->validate($token)->uid())->toBe(TokenFactory::UID);
});

it('throttles forced refetches so unknown kids cannot hammer the auth server', function (): void {
    $impostor = new TokenFactory('never-published');
    $token = $impostor->sign($impostor->payload());

    // Warm the cache first, so the cold-cache fetch is not part of the count.
    $this->validator()->validate($this->tokens->sign($this->tokens->payload()));
    $warm = count(Http::recorded());

    // The first unknown kid spends the one refetch slot in the window — that is
    // how a rotation we have not seen yet gets picked up.
    rejects(fn () => $this->validator()->validate($token));

    expect(count(Http::recorded()))->toBe($warm + 1);

    // Every further unknown kid inside the window costs nothing. Without the
    // throttle, anyone can point garbage kids at us and have us DDoS the auth
    // server on their behalf.
    rejects(fn () => $this->validator()->validate($token));
    rejects(fn () => $this->validator()->validate($token));
    rejects(fn () => $this->validator()->validate($token));

    expect(count(Http::recorded()))->toBe($warm + 1);
});

it('does not fetch the same JWKS document twice for one unknown kid on a cold cache', function (): void {
    $impostor = new TokenFactory('never-published');

    rejects(fn () => $this->validator()->validate($impostor->sign($impostor->payload())));

    // The fetch that filled the cold cache IS the fresh copy; refetching it
    // microseconds later asks the same URL the same question.
    expect(count(Http::recorded()))->toBe(1);
});

it('keeps validating from the cache while the JWKS endpoint is down', function (): void {
    $this->validator()->validate($this->tokens->sign($this->tokens->payload()));

    $this->breakJwksEndpoint();

    $claims = $this->validator()->validate($this->tokens->sign($this->tokens->payload()));

    expect($claims->uid())->toBe(TokenFactory::UID);
});

it('falls back to the bundled key when the endpoint is unreachable on a cold cache', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', [$this->tokens->jwk()]);
    $this->app->forgetInstance(JwksClient::class);
    $this->app->forgetInstance(TokenValidator::class);

    $this->breakJwksEndpoint();

    $claims = $this->validator()->validate($this->tokens->sign($this->tokens->payload()));

    expect($claims->uid())->toBe(TokenFactory::UID);
});

/*
 * A failed refetch is not knowledge. Found live on Coms Coupler, 19 Sep 2026:
 * key rotated, JWKS down, cache cold, bundle carrying only the old kid — every
 * token signed by the new key answered 401 `token_signing_key_unknown`, and
 * the holder was sent back through login for an outage on our side. The kid
 * was never checked against the auth server; the client had simply run out of
 * places to look. That is the fetch's 503, not the token's 401.
 */
it('reports 503 when the endpoint is down, the cache is cold and the bundle lacks the kid', function (): void {
    config()->set('wollerp-auth.jwks.bundled_keys', [$this->tokens->jwk()]);
    $this->app->forgetInstance(JwksClient::class);
    $this->app->forgetInstance(TokenValidator::class);
    $this->breakJwksEndpoint();

    $rotated = new TokenFactory('2026-12');
    $exception = rejects(fn () => $this->validator()->validate($rotated->sign($rotated->payload())));

    expect($exception->reason())->toBe('jwks_unavailable')
        ->and($exception->status())->toBe(503);

    // The bundled kid still validates from the same cold, broken state.
    expect($this->validator()->validate($this->tokens->sign($this->tokens->payload()))->uid())
        ->toBe(TokenFactory::UID);
});

it('reports 503 when the forced refetch for an unknown kid fails against a warm cache', function (): void {
    // Warm with the old key, then the endpoint dies and a rotated key arrives.
    $this->validator()->validate($this->tokens->sign($this->tokens->payload()));
    $this->breakJwksEndpoint();

    $rotated = new TokenFactory('2026-12');
    $exception = rejects(fn () => $this->validator()->validate($rotated->sign($rotated->payload())));

    expect($exception->reason())->toBe('jwks_unavailable')
        ->and($exception->status())->toBe(503);
});

it('still answers 401 for an unknown kid when the refetch is throttled, because nothing failed', function (): void {
    $impostor = new TokenFactory('never-published');
    $token = $impostor->sign($impostor->payload());

    // Warm, then spend the refetch slot on a LIVE answer that lacks the kid.
    $this->validator()->validate($this->tokens->sign($this->tokens->payload()));
    rejects(fn () => $this->validator()->validate($token));

    // Now the endpoint dies. Inside the cooldown no fetch runs, so there is no
    // failure to report — the kid is absent from a fresh document, full stop.
    $this->breakJwksEndpoint();
    $exception = rejects(fn () => $this->validator()->validate($token));

    expect($exception->reason())->toBe('token_signing_key_unknown')
        ->and($exception->status())->toBe(401);
});

it('reports a JWKS outage as 503, not as a bad token', function (): void {
    $this->breakJwksEndpoint();

    $exception = rejects(
        fn () => $this->validator()->validate($this->tokens->sign($this->tokens->payload()))
    );

    expect($exception->reason())->toBe('jwks_unavailable')
        ->and($exception->status())->toBe(503);
});

it('ignores non-RSA and non-signing entries in the JWKS document', function (): void {
    $this->publishJwks(
        ['kty' => 'oct', 'kid' => $this->tokens->kid, 'k' => 'c2VjcmV0'],
        ['kty' => 'EC', 'kid' => 'ec-key', 'crv' => 'P-256', 'x' => 'AA', 'y' => 'BB'],
        $this->tokens->jwk(),
    );

    expect($this->validator()->validate($this->tokens->sign($this->tokens->payload()))->uid())
        ->toBe(TokenFactory::UID);
});

/**
 * An `oct` entry reaching a verifier is how HMAC confusion attacks start, so it
 * is dropped at cache-write time rather than stored. If it is the ONLY entry
 * published we hold no key material at all — which is a 503, but a different
 * 503 from an outage: nobody needs to check whether the auth server is up,
 * somebody needs to look at what it is publishing.
 */
it('reports a JWKS document with no usable key as unusable, not unreachable', function (array $useless): void {
    $this->publishJwks($useless);

    $exception = rejects(
        fn () => $this->validator()->validate($this->tokens->sign($this->tokens->payload()))
    );

    expect($exception->reason())->toBe('jwks_unusable')
        ->and($exception->status())->toBe(503);
})->with(function () {
    $kid = TokenFactory::shared()->kid;

    return [
        'oct only' => [['kty' => 'oct', 'kid' => $kid, 'alg' => 'HS256', 'k' => 'c2VjcmV0']],
        'ec only' => [['kty' => 'EC', 'kid' => $kid, 'crv' => 'P-256', 'x' => 'AA', 'y' => 'BB']],
        'encryption use' => [['kty' => 'RSA', 'use' => 'enc', 'kid' => $kid, 'n' => 'AA', 'e' => 'AQAB']],
    ];
});

it('drops an undersized RSA key without dropping the good one beside it', function (): void {
    // Through the forge's helper, not a bare openssl_pkey_new(): on a host with
    // no OpenSSL config this returns false and the TypeError from passing it to
    // openssl_pkey_get_details() reads as a broken test rather than a missing
    // config file.
    $weak = openssl_pkey_new(TokenForge::withOpenSslConfig([
        'private_key_bits' => 1024,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]));

    expect($weak)->not->toBeFalse('could not generate the undersized key this test needs');

    $details = openssl_pkey_get_details($weak);

    $this->publishJwks(
        [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => 'weak',
            'n' => Base64Url::encode((string) $details['rsa']['n']),
            'e' => Base64Url::encode((string) $details['rsa']['e']),
        ],
        $this->tokens->jwk(),
    );

    // 2048 bits is the floor. A 1024-bit key is not one we should ever be asked
    // to trust, and publishing one must not take the real key down with it.
    expect($this->validator()->validate($this->tokens->sign($this->tokens->payload()))->uid())
        ->toBe(TokenFactory::UID);

    $forged = new TokenFactory('weak');

    expect(rejects(fn () => $this->validator()->validate($forged->sign($forged->payload())))->reason())
        ->toBe('token_signing_key_unknown');
});

it('rejects a token with no kid in the header', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(), ['kid' => null]);

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_malformed');
});
