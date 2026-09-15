<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Hmac;

use Closure;
use InvalidArgumentException;

/**
 * CONTRACT §5 — outbound half of the service plane.
 *
 *   X-Wollerp-Project:   cc
 *   X-Wollerp-Timestamp: 1757808000
 *   X-Wollerp-Signature: sha256=hash_hmac('sha256', "{timestamp}.{raw_body}", $secret)
 *
 * The signed string is `{timestamp}.{raw_body}` — the timestamp is inside the
 * MAC, so it cannot be edited in flight to replay an old request into a fresh
 * window. The body is the RAW bytes that go on the wire: JSON re-encoding
 * changes key order, unicode escaping and float formatting, and the receiver
 * would then MAC different bytes than we did.
 */
final class Signer
{
    public const PROJECT_HEADER = 'X-Wollerp-Project';

    public const TIMESTAMP_HEADER = 'X-Wollerp-Timestamp';

    public const SIGNATURE_HEADER = 'X-Wollerp-Signature';

    /**
     * @param  Closure(): int|null  $clock
     */
    public function __construct(
        private readonly string $project,
        private readonly string $secret,
        private readonly ?Closure $clock = null,
    ) {
        if ($project === '') {
            throw new InvalidArgumentException(
                'Refusing to construct a Signer without a project slug; set WOLLERP_SERVICE_SLUG '
                .'(CONTRACT §7 — the registry is open, so this package ships no default).'
            );
        }

        if ($secret === '') {
            throw new InvalidArgumentException(
                'Refusing to construct a Signer with an empty secret; set WOLLERP_HMAC_SECRET_AUTH.'
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
     * @return string the full header value, including the `sha256=` prefix
     */
    public function sign(string $rawBody, int $timestamp): string
    {
        return 'sha256='.hash_hmac('sha256', $timestamp.'.'.$rawBody, $this->secret);
    }

    public function project(): string
    {
        return $this->project;
    }
}
