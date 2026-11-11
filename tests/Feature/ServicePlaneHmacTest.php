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
function internalRequest(string $body, array $headers, string $uri = '/api/v1/internal/revoke', string $method = 'POST'): Request
{
    $server = [];

    foreach ($headers as $name => $value) {
        $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
    }

    $server['CONTENT_TYPE'] = 'application/json';

    return Request::create($uri, $method, server: $server, content: $body);
}

/**
 * v2 headers for the request a test is about to build.
 *
 * @return array<string, string>
 */
function v2Headers(Signer $signer, string $method, string $target, string $body, ?int $timestamp = null): array
{
    $timestamp ??= time();

    return [
        Signer::PROJECT_HEADER => $signer->project(),
        Signer::TIMESTAMP_HEADER => (string) $timestamp,
        Signer::VERSION_HEADER => Signer::VERSION_2,
        Signer::SIGNATURE_HEADER => $signer->signV2($method, $target, $body, $timestamp),
    ];
}

beforeEach(function (): void {
    $this->secret = 'inbound-test-secret';
    $this->signer = new Signer('auth', $this->secret);
    $this->verifier = new Verifier(['auth' => $this->secret]);
    $this->body = json_encode(['sid' => '01JBZ3K5M7N9P1Q3R5S7T9V1W3', 'jti' => null, 'not_after' => 1757808900]);
});

it('produces the three v1 contract headers (signRequest upgrades them to v2 on the wire)', function (): void {
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

it('accepts a signed request once and refuses the same signature again', function (): void {
    $middleware = new VerifyHmacSignature($this->verifier, [], new Illuminate\Cache\Repository(new Illuminate\Cache\ArrayStore));
    $headers = $this->signer->headers($this->body);
    $next = fn (): Response => new Response('ok');

    $first = $middleware->handle(internalRequest($this->body, $headers), $next);
    // Same bytes, same headers, other endpoint — a captured confirm replayed as a release.
    $replay = $middleware->handle(internalRequest($this->body, $headers), $next);

    expect($first->getStatusCode())->toBe(200)
        ->and($replay->getStatusCode())->toBe(401)
        ->and($replay->getContent())->toContain('signature_replayed');
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

/*
|--------------------------------------------------------------------------
| v2 — method and request-target inside the MAC (CONTRACT §5)
|--------------------------------------------------------------------------
*/

/*
 * Golden vector. The SAME constants and digest are asserted in wollerp-auth's
 * tests/Feature/ServicePlane/HmacSignatureTest.php, so both implementations are
 * pinned to one string format rather than merely to each other.
 */
it('matches the cross-codebase v2 golden vector', function (): void {
    $body = '{"sid":"01JBZ3K5M7N9P1Q3R5S7T9V1W3","jti":null,"not_after":"2026-09-15T12:20:00+00:00","reason":"logout"}';
    $golden = 'sha256=37f3e94d40b37a9c7b8a289bef1120e1b402e173e3222c9bbe3fe0a401910462';

    expect(Signer::canonicalV2(1757808000, 'post', '/api/v1/internal/revoke', $body))
        ->toBe('1757808000.POST./api/v1/internal/revoke.'.$body)
        ->and((new Signer('auth', 'wollerp-golden-secret'))->signV2('POST', '/api/v1/internal/revoke', $body, 1757808000))
        ->toBe($golden);

    (new Verifier(['auth' => 'wollerp-golden-secret'], clock: fn (): int => 1757808000))
        ->verify('auth', '1757808000', $golden, $body, 'POST', '/api/v1/internal/revoke', '2');
});

it('accepts a v2 signature over the right method and target', function (): void {
    $h = v2Headers($this->signer, 'POST', '/api/v1/internal/handles/confirm', $this->body);

    $this->verifier->verify('auth', $h[Signer::TIMESTAMP_HEADER], $h[Signer::SIGNATURE_HEADER], $this->body, 'POST', '/api/v1/internal/handles/confirm', '2');
})->throwsNoExceptions();

it('refuses a v2 confirm re-aimed at release, or sent with another method or target', function (string $method, string $target): void {
    $h = v2Headers($this->signer, 'POST', '/api/v1/internal/handles/confirm', $this->body);

    expect(rejects(fn () => $this->verifier->verify(
        'auth', $h[Signer::TIMESTAMP_HEADER], $h[Signer::SIGNATURE_HEADER], $this->body, $method, $target, '2',
    ))->reason())->toBe('signature_mismatch');
})->with([
    'confirm -> release' => ['POST', '/api/v1/internal/handles/release'],
    'POST -> PUT' => ['PUT', '/api/v1/internal/handles/confirm'],
    'query appended' => ['POST', '/api/v1/internal/handles/confirm?x=1'],
    'trailing slash' => ['POST', '/api/v1/internal/handles/confirm/'],
]);

it('refuses a v2 signature with a tampered body or timestamp', function (): void {
    $ts = time();
    $sig = $this->signer->signV2('POST', '/api/v1/internal/revoke', $this->body, $ts);

    expect(rejects(fn () => $this->verifier->verify('auth', (string) $ts, $sig, $this->body.' ', 'POST', '/api/v1/internal/revoke', '2'))->reason())
        ->toBe('signature_mismatch')
        ->and(rejects(fn () => $this->verifier->verify('auth', (string) ($ts - 1), $sig, $this->body, 'POST', '/api/v1/internal/revoke', '2'))->reason())
        ->toBe('signature_mismatch');
});

it('refuses a v1 signature labelled v2, and an unknown version', function (): void {
    $ts = time();
    $v1 = $this->signer->sign($this->body, $ts);

    expect(rejects(fn () => $this->verifier->verify('auth', (string) $ts, $v1, $this->body, 'POST', '/api/v1/internal/revoke', '2'))->reason())
        ->toBe('signature_mismatch')
        ->and(rejects(fn () => $this->verifier->verify('auth', (string) $ts, $v1, $this->body, 'POST', '/api/v1/internal/revoke', '3'))->reason())
        ->toBe('signature_version_refused');
});

it('accepts v1 only while accept_v1 is on; v2 is unaffected by the flag', function (): void {
    $ts = time();
    $v1 = $this->signer->sign($this->body, $ts);
    $strict = new Verifier(['auth' => $this->secret], acceptV1: false);

    $this->verifier->verify('auth', (string) $ts, $v1, $this->body, 'POST', '/api/v1/internal/revoke');

    expect(rejects(fn () => $strict->verify('auth', (string) $ts, $v1, $this->body, 'POST', '/api/v1/internal/revoke'))->reason())
        ->toBe('signature_version_refused');

    $strict->verify('auth', (string) $ts, $this->signer->signV2('POST', '/api/v1/internal/revoke', $this->body, $ts), $this->body, 'POST', '/api/v1/internal/revoke', '2');
});

it('takes accept_v1 from config, defaulting to on', function (): void {
    $ts = time();
    $v1 = $this->signer->sign($this->body, $ts);
    config(['wollerp-auth.hmac.secrets' => ['auth' => $this->secret]]);

    app()->forgetInstance(Verifier::class);
    app(Verifier::class)->verify('auth', (string) $ts, $v1, $this->body);

    config(['wollerp-auth.hmac.accept_v1' => false]);
    app()->forgetInstance(Verifier::class);

    expect(rejects(fn () => app(Verifier::class)->verify('auth', (string) $ts, $v1, $this->body))->reason())
        ->toBe('signature_version_refused');
});

it('verifies v2 at the middleware against the received request-target, query included', function (): void {
    $middleware = new VerifyHmacSignature($this->verifier);
    $next = fn (): Response => new Response('ok');
    $target = '/api/v1/internal/users?since=2026-01-01T00%3A00%3A00%2B00%3A00&page=2';
    $headers = v2Headers($this->signer, 'GET', $target, '');

    $ok = $middleware->handle(internalRequest('', $headers, $target, 'GET'), $next);
    $otherQuery = $middleware->handle(internalRequest('', $headers, '/api/v1/internal/users?since=1970-01-01&page=2', 'GET'), $next);

    expect($ok->getStatusCode())->toBe(200)
        ->and($otherQuery->getStatusCode())->toBe(401);
});

it('refuses a captured v2 confirm replayed at release through the middleware, even with no replay cache', function (): void {
    $middleware = new VerifyHmacSignature($this->verifier);
    $headers = v2Headers($this->signer, 'POST', '/api/v1/internal/handles/confirm', $this->body);
    $next = fn (): Response => new Response('ok');

    $confirm = $middleware->handle(internalRequest($this->body, $headers, '/api/v1/internal/handles/confirm'), $next);
    $release = $middleware->handle(internalRequest($this->body, $headers, '/api/v1/internal/handles/release'), $next);

    expect($confirm->getStatusCode())->toBe(200)
        ->and($release->getStatusCode())->toBe(401)
        ->and($release->getContent())->toContain('signature_mismatch');
});

it('runs a v1 signature through the replay guard too', function (): void {
    $middleware = new VerifyHmacSignature($this->verifier, [], new Illuminate\Cache\Repository(new Illuminate\Cache\ArrayStore));
    $headers = $this->signer->headers($this->body);
    $next = fn (): Response => new Response('ok');

    expect($middleware->handle(internalRequest($this->body, $headers), $next)->getStatusCode())->toBe(200)
        ->and($middleware->handle(internalRequest($this->body, $headers), $next)->getContent())->toContain('signature_replayed');
});

it('refuses a v1 request at the middleware when accept_v1 is off', function (): void {
    $middleware = new VerifyHmacSignature(new Verifier(['auth' => $this->secret], acceptV1: false));

    $response = $middleware->handle(internalRequest($this->body, $this->signer->headers($this->body)), fn (): Response => new Response('ok'));

    expect($response->getStatusCode())->toBe(401)
        ->and($response->getContent())->toContain('signature_version_refused');
});

it('still passes the request when the replay cache throws', function (): void {
    $store = new class extends Illuminate\Cache\ArrayStore
    {
        public function add($key, $value, $seconds)
        {
            throw new RuntimeException('cache down');
        }
    };

    $middleware = new VerifyHmacSignature($this->verifier, [], new Illuminate\Cache\Repository($store));
    $headers = v2Headers($this->signer, 'POST', '/api/v1/internal/revoke', $this->body);

    expect($middleware->handle(internalRequest($this->body, $headers), fn (): Response => new Response('ok'))->getStatusCode())
        ->toBe(200);
});

it('upgrades its own v1 outbound request to v2 and leaves foreign ones alone', function (): void {
    $ts = time();
    $psr = new GuzzleHttp\Psr7\Request('POST', 'https://accounts.example/api/v1/internal/handles/confirm?x=1', $this->signer->headers($this->body, $ts), $this->body);

    $signed = $this->signer->signRequest($psr);

    expect($signed->getHeaderLine(Signer::VERSION_HEADER))->toBe('2')
        ->and($signed->getHeaderLine(Signer::SIGNATURE_HEADER))
        ->toBe($this->signer->signV2('POST', '/api/v1/internal/handles/confirm?x=1', $this->body, $ts))
        ->and((string) $signed->getBody())->toBe($this->body);

    // Signed with a different pair secret: not this signer's to re-sign.
    $foreign = new GuzzleHttp\Psr7\Request('POST', 'https://x.example/y', (new Signer('auth', 'other'))->headers($this->body, $ts), $this->body);
    $plain = new GuzzleHttp\Psr7\Request('GET', 'https://x.example/y');

    expect($this->signer->signRequest($foreign))->toBe($foreign)
        ->and($this->signer->signRequest($plain))->toBe($plain);
});
