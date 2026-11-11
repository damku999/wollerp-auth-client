<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Hmac;

use Closure;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT §5 — outbound half of the service plane.
 *
 *   X-Wollerp-Project:           cc
 *   X-Wollerp-Timestamp:         1757808000
 *   X-Wollerp-Signature-Version: 2
 *   X-Wollerp-Signature:         sha256=hash_hmac('sha256', "{timestamp}.{METHOD}.{target}.{raw_body}", $secret)
 *
 * v2 (§5, 0.4.0) binds the METHOD and the request-target (path plus raw query,
 * exactly as on the request line) into the MAC, so a captured handles/confirm
 * cannot be re-aimed at handles/release with the same body. v1 was
 * `{timestamp}.{raw_body}` with no version header; it is still produced by
 * headers()/sign() for a caller that has no request to sign, and is upgraded to
 * v2 by signRequest() — which the service provider installs as a global Laravel
 * HTTP client middleware, so every `Http`/HttpFactory call carrying these
 * headers leaves signed v2 without its call site knowing the path.
 *
 * The timestamp is inside the MAC, so it cannot be edited in flight to replay
 * an old request into a fresh window. The body is the RAW bytes that go on the
 * wire: JSON re-encoding changes key order, unicode escaping and float
 * formatting, and the receiver would then MAC different bytes than we did.
 */
final class Signer
{
    public const PROJECT_HEADER = 'X-Wollerp-Project';

    public const TIMESTAMP_HEADER = 'X-Wollerp-Timestamp';

    public const SIGNATURE_HEADER = 'X-Wollerp-Signature';

    public const VERSION_HEADER = 'X-Wollerp-Signature-Version';

    public const VERSION_2 = '2';

    /**
     * @param  Closure(): int|null  $clock
     */
    public function __construct(
        private readonly string $project,
        private readonly string $secret,
        private readonly ?Closure $clock = null,
    ) {
        // Deliberately NO validation here. See assertUsable().
    }

    /**
     * Fail closed at USE time, not at construction time.
     *
     * These guards lived in the constructor, which looked stricter and was
     * actively worse: this class is bound as a singleton by the service
     * provider and injected into SyncUsersCommand. `#[AsCommand]` defers
     * *targeted* invocation but NOT *enumeration* — anything that calls
     * Application::all() constructs every command, so on a checkout without
     * WOLLERP_HMAC_SECRET_AUTH set, `php artisan list`, `artisan tinker` and
     * `artisan` with no arguments all died at boot. A consumer could not even
     * run the tinker check that INTEGRATION.md §3 prescribes.
     *
     * Moving the guard here keeps the security property exactly — nothing can
     * sign with an empty secret or an empty project — while letting the object
     * exist unconfigured. Signing is the operation that must refuse; existing
     * is not.
     */
    private function assertUsable(): void
    {
        if ($this->project === '') {
            throw new InvalidArgumentException(
                'Refusing to sign without a project slug; set WOLLERP_SERVICE_SLUG '
                .'(CONTRACT §7 — the registry is open, so this package ships no default).'
            );
        }

        if ($this->secret === '') {
            throw new InvalidArgumentException(
                'Refusing to sign with an empty secret; set WOLLERP_HMAC_SECRET_AUTH.'
            );
        }
    }

    /**
     * @return array{'X-Wollerp-Project': string, 'X-Wollerp-Timestamp': string, 'X-Wollerp-Signature': string}
     */
    public function headers(string $rawBody, ?int $timestamp = null): array
    {
        $timestamp ??= $this->clock !== null ? ($this->clock)() : time();

        return [
            self::PROJECT_HEADER => $this->project,
            self::TIMESTAMP_HEADER => (string) $timestamp,
            self::SIGNATURE_HEADER => $this->sign($rawBody, $timestamp),
        ];
    }

    /**
     * v1 header value, including the `sha256=` prefix. Path-unaware; kept for
     * the transition and for headers(). New code signs with signV2().
     */
    public function sign(string $rawBody, int $timestamp): string
    {
        $this->assertUsable();

        return self::mac($this->secret, $timestamp.'.'.$rawBody);
    }

    /**
     * v2 header value. `$target` is the request-target: path plus `?query` if
     * any, as it appears on the request line.
     */
    public function signV2(string $method, string $target, string $rawBody, int $timestamp): string
    {
        $this->assertUsable();

        return self::mac($this->secret, self::canonicalV2($timestamp, $method, $target, $rawBody));
    }

    /**
     * Re-sign an outbound PSR-7 request as v2, over its real method, request
     * target and body.
     *
     * Only a request that carries THIS signer's project header and a v1
     * signature this signer produced is touched — everything else passes
     * through unchanged. That makes it safe as a global HTTP client middleware:
     * it never signs a request it did not already sign, and a request signed by
     * a different Signer instance (another secret) keeps its own signature.
     */
    public function signRequest(RequestInterface $request): RequestInterface
    {
        if ($this->project === '' || $this->secret === ''
            || $request->getHeaderLine(self::PROJECT_HEADER) !== $this->project
            || $request->hasHeader(self::VERSION_HEADER)) {
            return $request;
        }

        $timestamp = $request->getHeaderLine(self::TIMESTAMP_HEADER);

        if (preg_match('/^\d{1,11}$/', $timestamp) !== 1) {
            return $request;
        }

        $body = $request->getBody();
        $rawBody = (string) $body;

        if ($body->isSeekable()) {
            $body->rewind();
        }

        if (! hash_equals($this->sign($rawBody, (int) $timestamp), $request->getHeaderLine(self::SIGNATURE_HEADER))) {
            return $request;
        }

        return $request
            ->withHeader(self::VERSION_HEADER, self::VERSION_2)
            ->withHeader(self::SIGNATURE_HEADER, $this->signV2(
                $request->getMethod(),
                $request->getRequestTarget(),
                $rawBody,
                (int) $timestamp,
            ));
    }

    /**
     * The v2 signed string. Shared with Verifier so the two cannot drift.
     *
     * Method is upper-cased. Target gets a leading `/` if it lacks one (an
     * empty path is `/`, as on the wire) and is otherwise used byte-for-byte:
     * no trailing-slash trimming, no decoding, no query re-ordering.
     */
    public static function canonicalV2(int|string $timestamp, string $method, string $target, string $rawBody): string
    {
        return $timestamp.'.'.strtoupper($method).'.'.self::normaliseTarget($target).'.'.$rawBody;
    }

    public static function normaliseTarget(string $target): string
    {
        return str_starts_with($target, '/') ? $target : '/'.$target;
    }

    private static function mac(string $secret, string $payload): string
    {
        return 'sha256='.hash_hmac('sha256', $payload, $secret);
    }

    public function project(): string
    {
        return $this->project;
    }
}
