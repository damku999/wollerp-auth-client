<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Exceptions;

use Throwable;

/**
 * CONTRACT §3. A JWKS problem is NOT the same class of event as a bad token:
 *
 * - `unknownKey` means the token names a `kid` nobody publishes. That is the
 *   token's fault → 401.
 * - `unreachable` means we hold no key material at all and could not fetch any.
 *   That is our fault → 503, so it shows up on an availability dashboard rather
 *   than being buried in the 401 noise.
 */
final class JwksException extends WollerpAuthException
{
    private function __construct(
        private readonly string $reason,
        private readonly int $status,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public function reason(): string
    {
        return $this->reason;
    }

    public function status(): int
    {
        return $this->status;
    }

    public static function unknownKey(string $kid): self
    {
        return new self(
            'token_signing_key_unknown',
            401,
            sprintf('No published signing key matches kid "%s".', $kid)
        );
    }

    public static function unreachable(string $url, ?Throwable $previous = null): self
    {
        return new self(
            'jwks_unavailable',
            503,
            sprintf('JWKS at %s is unreachable and no key material is cached or bundled.', $url),
            $previous
        );
    }

    /**
     * Reachable, parseable, and containing no key this verifier will trust.
     * Separated from `unreachable` because the remedy is different: nobody
     * needs to check whether the auth server is up — somebody needs to look at
     * what it is publishing.
     */
    public static function unusable(string $url): self
    {
        return new self(
            'jwks_unusable',
            503,
            sprintf(
                'JWKS at %s published no usable RS256 signing key; every entry was rejected '
                .'as non-RSA, non-signing, undersized or malformed.',
                $url
            )
        );
    }
}
