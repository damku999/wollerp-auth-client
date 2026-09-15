<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Exceptions;

use RuntimeException;

/**
 * Base for everything this package throws. Catch this in a product's exception
 * handler to map the whole family onto that product's response envelope.
 */
abstract class WollerpAuthException extends RuntimeException
{
    /**
     * Stable machine-readable reason. Safe to return to the caller.
     */
    public function reason(): string
    {
        return 'auth_error';
    }

    /**
     * HTTP status this exception maps to.
     */
    public function status(): int
    {
        return 401;
    }
}
