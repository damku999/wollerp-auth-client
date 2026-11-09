<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Exceptions;

use RuntimeException;
use Throwable;

/**
 * A handle call (CONTRACT §5.6) that did not succeed.
 *
 * Two families, told apart by reason():
 *
 *   - Auth answered and refused: `taken`, `already_set`, `not_reserved`,
 *     `user_not_found`, `account_required` — the HDL_* codes, carrying the HTTP
 *     status Auth chose (409 / 404 / 422).
 *   - Auth did not answer usefully: `unavailable` (503) — connection refused,
 *     timeout, TLS, a 5xx, an unsigned call or a body we cannot read. Products
 *     must fail the handle write closed on this, never guess.
 *
 * Deliberately NOT a WollerpAuthException: products map that family to a token
 * error ("sign in again"), which is the wrong message for a taken handle.
 */
final class HandleRegistryException extends RuntimeException
{
    public const TAKEN = 'taken';

    public const ALREADY_SET = 'already_set';

    public const NOT_RESERVED = 'not_reserved';

    public const USER_NOT_FOUND = 'user_not_found';

    public const ACCOUNT_REQUIRED = 'account_required';

    public const UNAVAILABLE = 'unavailable';

    /** Auth's config/error_codes.php `handle.*`, the only part of a refusal we branch on. */
    public const CODES = [
        'HDL_001' => self::TAKEN,
        'HDL_002' => self::ALREADY_SET,
        'HDL_003' => self::NOT_RESERVED,
        'HDL_004' => self::USER_NOT_FOUND,
        'HDL_005' => self::ACCOUNT_REQUIRED,
    ];

    private function __construct(
        private readonly string $reason,
        private readonly int $status,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function refused(string $reason, int $status): self
    {
        return new self($reason, $status, sprintf('Auth refused the handle call: %s.', $reason));
    }

    public static function unavailable(string $detail, ?Throwable $previous = null): self
    {
        return new self(self::UNAVAILABLE, 503, 'Handle registry unavailable: '.$detail, $previous);
    }

    public function reason(): string
    {
        return $this->reason;
    }

    public function status(): int
    {
        return $this->status;
    }

    public function isUnavailable(): bool
    {
        return $this->reason === self::UNAVAILABLE;
    }
}
