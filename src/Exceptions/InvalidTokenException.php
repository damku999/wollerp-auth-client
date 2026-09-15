<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Exceptions;

/**
 * Layer 1 failure — CONTRACT §2. Always a 401.
 *
 * The `reason` is deliberately coarse. It tells an integrator what went wrong
 * without telling an attacker which of several checks they are closest to
 * passing, and it never echoes token content back.
 */
final class InvalidTokenException extends WollerpAuthException
{
    private function __construct(
        private readonly string $reason,
        string $message,
    ) {
        parent::__construct($message);
    }

    public function reason(): string
    {
        return $this->reason;
    }

    public static function missing(): self
    {
        return new self('token_missing', 'No bearer token on the request.');
    }

    public static function malformed(string $detail = 'Token is not a well-formed JWS.'): self
    {
        return new self('token_malformed', $detail);
    }

    public static function tooLarge(int $limit): self
    {
        return new self('token_malformed', "Token exceeds the {$limit} byte limit.");
    }

    /**
     * alg:none and HS256-signed-with-the-RSA-public-key both land here.
     */
    public static function unsupportedAlgorithm(string $presented): self
    {
        return new self(
            'token_algorithm_not_allowed',
            sprintf('Only RS256 is accepted; token header presented "%s".', $presented)
        );
    }

    public static function missingKeyId(): self
    {
        return new self('token_malformed', 'Token header has no `kid`.');
    }

    public static function signatureMismatch(): self
    {
        return new self('token_signature_invalid', 'RSA signature verification failed.');
    }

    public static function expired(): self
    {
        return new self('token_expired', 'Token `exp` is in the past.');
    }

    public static function notYetValid(): self
    {
        return new self('token_not_yet_valid', 'Token `nbf` is in the future.');
    }

    public static function issuedInFuture(): self
    {
        return new self('token_not_yet_valid', 'Token `iat` is in the future.');
    }

    public static function issuerMismatch(): self
    {
        return new self('token_issuer_mismatch', 'Token `iss` is not the expected issuer.');
    }

    public static function audienceMismatch(): self
    {
        return new self('token_audience_mismatch', 'Token `aud` does not contain this service.');
    }

    public static function missingClaim(string $claim): self
    {
        return new self('token_claims_invalid', "Token is missing or has a bad `{$claim}` claim.");
    }
}
