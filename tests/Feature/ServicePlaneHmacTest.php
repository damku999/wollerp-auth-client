<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Wollerp\AuthClient\Exceptions\InvalidServiceSignatureException;
use Wollerp\AuthClient\Hmac\Signer;
use Wollerp\AuthClient\Hmac\Verifier;
use Wollerp\AuthClient\Http\Middleware\VerifyHmacSignature;

/**
 * CONTRACT §5.
 */
function internalRequest(string $body, array $headers): Request
{
    $server = [];

    foreach ($headers as $name => $value) {
        $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
    }

    $server['CONTENT_TYPE'] = 'application/json';

    return Request::create('/api/v1/internal/revoke', 'POST', server: $server, content: $body);
}

beforeEach(function (): void {
    $this->secret = 'inbound-test-secret';
    $this->signer = new Signer('auth', $this->secret);
    $this->verifier = new Verifier(['auth' => $this->secret]);
    $this->body = json_encode(['sid' => '01JBZ3K5M7N9P1Q3R5S7T9V1W3', 'jti' => null, 'not_after' => 1757808900]);
});

it('produces the three contract headers', function (): void {
    $headers = $this->signer->headers($this->body, 1757808000);

    expect($headers)->toHaveKeys(['X-Wollerp-Project', 'X-Wollerp-Timestamp', 'X-Wollerp-Signature'])
        ->and($headers['X-Wollerp-Project'])->toBe('auth')
        ->and($headers['X-Wollerp-Timestamp'])->toBe('1757808000')
        ->and($headers['X-Wollerp-Signature'])->toBe(
            'sha256='.hash_hmac('sha256', '1757808000.'.$this->body, $this->secret)
        );
});

it('accepts a correctly signed call', function (): void {
    $headers = $this->signer->headers($this->body);

    $this->verifier->verify(
        $headers['X-Wollerp-Project'],
        $headers['X-Wollerp-Timestamp'],
        $headers['X-Wollerp-Signature'],
        $this->body,
    );
})->throwsNoExceptions();

it('rejects a body altered after signing', function (): void {
    $headers = $this->signer->headers($this->body);

    expect(fn () => $this->verifier->verify(
        $headers['X-Wollerp-Project'],
        $headers['X-Wollerp-Timestamp'],
        $headers['X-Wollerp-Signature'],
        str_replace('01JBZ3K5M7N9P1Q3R5S7T9V1W3', '01JATTACKERSESSION000000AA', $this->body),
    ))->toThrow(InvalidServiceSignatureException::class);
});

it('rejects a timestamp moved after signing, because the timestamp is inside the MAC', function (): void {
    $headers = $this->signer->headers($this->body, time() - 400);

    expect(fn () => $this->verifier->verify(
        $headers['X-Wollerp-Project'],
        (string) time(),
        $headers['X-Wollerp-Signature'],
        $this->body,
    ))->toThrow(InvalidServiceSignatureException::class);
});

it('rejects calls outside the 300 second window in both directions', function (int $offset): void {
    $timestamp = time() + $offset;
    $signature = $this->signer->sign($this->body, $timestamp);

    $exception = rejects(fn () => $this->verifier->verify('auth', (string) $timestamp, $signature, $this->body));

    expect($exception->reason())->toBe('signature_timestamp_outside_window');
})->with(['replay' => -301, 'future' => 301, 'far replay' => -86400]);

it('accepts calls at the edges of the window', function (int $offset): void {
    $timestamp = time() + $offset;

    $this->verifier->verify('auth', (string) $timestamp, $this->signer->sign($this->body, $timestamp), $this->body);
})->with([-299, 0, 299])->throwsNoExceptions();

it('rejects an unknown calling project', function (): void {
    $timestamp = time();

    $exception = rejects(fn () => $this->verifier->verify(
        'attacker',
        (string) $timestamp,
        $this->signer->sign($this->body, $timestamp),
        $this->body,
    ));

    expect($exception->reason())->toBe('signature_project_unknown');
});

it('rejects a signature produced with a different pair secret', function (): void {
    $otherPair = new Signer('auth', 'a-different-service-pair-secret');
    $headers = $otherPair->headers($this->body);

    expect(rejects(fn () => $this->verifier->verify(
        'auth',
        $headers['X-Wollerp-Timestamp'],
        $headers['X-Wollerp-Signature'],
        $this->body,
    ))->reason())->toBe('signature_mismatch');
});

it('rejects malformed and missing headers', function (?string $timestamp, ?string $signature, string $reason): void {
    expect(rejects(fn () => $this->verifier->verify('auth', $timestamp, $signature, $this->body))->reason())
        ->toBe($reason);
})->with([
    'no timestamp' => [null, 'sha256=deadbeef', 'signature_timestamp_invalid'],
    'non numeric' => ['not-a-time', 'sha256=deadbeef', 'signature_timestamp_invalid'],
    'scientific notation' => ['1e10', 'sha256=deadbeef', 'signature_timestamp_invalid'],
    'no signature' => [null, null, 'signature_timestamp_invalid'],
]);

/*
 * The guard moved from the constructor to the signing path, and this test moved
 * with it. The security property is unchanged and is now asserted more
 * thoroughly than before: nothing can produce a signature without a secret, and
 * nothing can produce one without a project slug.
 *
 * What changed is only WHEN it refuses. The constructor throw was not stricter,
 * it was broken. This class is bound as a singleton and injected into
 * SyncUsersCommand; `#[AsCommand]` defers targeted invocation but NOT
 * enumeration, so anything reaching Application::all() constructs it. On a
 * consumer not yet issued WOLLERP_HMAC_SECRET_AUTH that meant `php artisan
 * list` and `php artisan tinker` died at boot — including the tinker check
 * INTEGRATION.md §3 tells integrators to run to verify the install.
 *
 * Constructing an unconfigured Signer is therefore allowed. Signing with one
 * is not.
 */
it('constructs with an empty secret but refuses to sign with one', function (): void {
    $signer = new Signer('cc', '');

    expect($signer)->toBeInstanceOf(Signer::class)
        ->and(fn () => $signer->sign('{}', 1757808000))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $signer->headers('{}'))->toThrow(InvalidArgumentException::class);
});

it('refuses to sign without a project slug', function (): void {
    $signer = new Signer('', 'a-real-secret');

    expect(fn () => $signer->sign('{}', 1757808000))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $signer->headers('{}'))->toThrow(InvalidArgumentException::class);
});

it('passes a correctly signed request through the middleware', function (): void {
    $middleware = new VerifyHmacSignature($this->verifier);
    $request = internalRequest($this->body, $this->signer->headers($this->body));

    $response = $middleware->handle($request, fn (): Response => new Response('ok'));

    expect($response->getStatusCode())->toBe(200)
        ->and($request->attributes->get(VerifyHmacSignature::PROJECT_ATTRIBUTE))->toBe('auth');
});

it('returns 401 from the middleware for a bad signature', function (): void {
    $middleware = new VerifyHmacSignature($this->verifier);

    $headers = $this->signer->headers($this->body);
    $headers['X-Wollerp-Signature'] = 'sha256='.str_repeat('0', 64);

    $response = $middleware->handle(
        internalRequest($this->body, $headers),
        fn (): Response => new Response('should not reach the controller'),
    );

    expect($response->getStatusCode())->toBe(401)
        ->and($response->getContent())->toContain('signature_mismatch');
});

it('enforces the IP allowlist as well as the signature', function (): void {
    $middleware = new VerifyHmacSignature($this->verifier, ['10.0.0.0/8']);

    $response = $middleware->handle(
        internalRequest($this->body, $this->signer->headers($this->body)),
        fn (): Response => new Response('should not reach the controller'),
    );

    expect($response->getStatusCode())->toBe(401)
        ->and($response->getContent())->toContain('ip_not_allowed');
});
