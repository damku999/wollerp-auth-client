<?php

declare(strict_types=1);

use Illuminate\Http\Response;
use Wollerp\AuthClient\Http\Middleware\Authenticate;
use Wollerp\AuthClient\Tests\Support\TokenFactory;
use Wollerp\AuthClient\Token\Claims;

beforeEach(function (): void {
    $this->middleware = $this->app->make(Authenticate::class);
});

it('passes a valid request through and attaches the claims', function (): void {
    $request = $this->requestWithToken($this->tokens->sign($this->tokens->payload()));

    $response = $this->middleware->handle($request, fn (): Response => new Response('ok'));

    expect($response->getStatusCode())->toBe(200)
        ->and(Authenticate::claims($request))->toBeInstanceOf(Claims::class)
        ->and(Authenticate::claims($request)->uid())->toBe(TokenFactory::UID)
        ->and($request->user()?->getAuthIdentifier())->toBe(TokenFactory::UID);
});

it('returns 401 with a bearer challenge and never reaches the controller', function (string $token): void {
    $reached = false;

    $response = $this->middleware->handle(
        $this->requestWithToken($token),
        function () use (&$reached): Response {
            $reached = true;

            return new Response('should not happen');
        },
    );

    expect($reached)->toBeFalse()
        ->and($response->getStatusCode())->toBe(401)
        ->and($response->headers->get('WWW-Authenticate'))->toStartWith('Bearer realm="wollerp"');
})->with(function () {
    $tokens = TokenFactory::shared();

    return [
        'alg none' => $tokens->algNone($tokens->payload()),
        'hs256 with public key' => $tokens->hs256WithPublicKey($tokens->payload()),
        'expired' => $tokens->sign($tokens->payload(['exp' => time() - 1800])),
        'wrong audience' => $tokens->sign($tokens->payload(['aud' => ['bc']])),
        'wrong issuer' => $tokens->sign($tokens->payload(['iss' => 'https://evil.example'])),
        'garbage' => 'not-even-a-token',
    ];
});

it('returns 401 when there is no Authorization header at all', function (): void {
    $response = $this->middleware->handle(
        Illuminate\Http\Request::create('/api/v1/example'),
        fn (): Response => new Response('should not happen'),
    );

    expect($response->getStatusCode())->toBe(401)
        ->and($response->getContent())->toContain('token_missing');
});

it('reports a JWKS outage as 503 without a bearer challenge', function (): void {
    $this->breakJwksEndpoint();

    $response = $this->middleware->handle(
        $this->requestWithToken($this->tokens->sign($this->tokens->payload())),
        fn (): Response => new Response('should not happen'),
    );

    // A 401 here would send the user back through login for an outage on our
    // side, and bury the incident in the 401 noise.
    expect($response->getStatusCode())->toBe(503)
        ->and($response->headers->has('WWW-Authenticate'))->toBeFalse()
        ->and($response->getContent())->toContain('jwks_unavailable');
});

it('does not leak which check failed beyond a coarse reason', function (): void {
    $response = $this->middleware->handle(
        $this->requestWithToken($this->tokens->sign($this->tokens->payload(['aud' => ['bc']]))),
        fn (): Response => new Response('should not happen'),
    );

    $body = json_decode((string) $response->getContent(), true);

    expect($body)->toHaveKeys(['success', 'error', 'reason'])
        ->and($body['success'])->toBeFalse()
        ->and($body)->not->toHaveKey('token')
        ->and($body)->not->toHaveKey('claims');
});
