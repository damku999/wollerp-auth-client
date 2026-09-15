<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Exceptions;

/**
 * Layer 2 failure — CONTRACT §2 step 8, §6. Always a 401.
 */
final class TokenRevokedException extends WollerpAuthException
{
    public static function make(): self
    {
        return new self('Token session or id is on the local denylist.');
    }

    public function reason(): string
    {
        return 'token_revoked';
    }
}
