<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Exceptions;

/**
 * Service plane failure — CONTRACT §5.
 */
final class InvalidServiceSignatureException extends WollerpAuthException
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

    public static function unknownProject(): self
    {
        return new self('signature_project_unknown', 'X-Wollerp-Project is missing or has no configured secret.');
    }

    public static function malformedTimestamp(): self
    {
        return new self('signature_timestamp_invalid', 'X-Wollerp-Timestamp is missing or not an integer.');
    }

    public static function staleTimestamp(int $window): self
    {
        return new self(
            'signature_timestamp_outside_window',
            "X-Wollerp-Timestamp is more than {$window} seconds from now."
        );
    }

    public static function mismatch(): self
    {
        return new self('signature_mismatch', 'X-Wollerp-Signature does not match the raw body.');
    }

    public static function ipNotAllowed(): self
    {
        return new self('ip_not_allowed', 'Caller IP is not on the internal allowlist.');
    }

    public static function secretNotConfigured(string $project): self
    {
        return new self('signature_secret_missing', "No HMAC secret configured for project \"{$project}\".");
    }
}
