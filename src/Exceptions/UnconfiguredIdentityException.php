<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Exceptions;

use RuntimeException;

/**
 * This product does not know which product it is.
 *
 * Deliberately NOT a WollerpAuthException. That family is the per-request
 * vocabulary — a product maps it onto 401 and 503 — and this is neither. It is a
 * deployment defect that must stop the container from booting, so mapping it
 * into the request envelope would be exactly the wrong thing: a 401 here would
 * send every user back through login for a missing line in a `.env`.
 */
final class UnconfiguredIdentityException extends RuntimeException
{
    public static function for(string $configKey, string $variable): self
    {
        return new self(sprintf(
            'wollerp-auth.%s is not configured. Set %s in .env (CONTRACT §7). There is '
            .'deliberately no default: an unset value must fail closed rather than inherit '
            .'another product\'s identity. If config is cached, run `php artisan config:clear`.',
            $configKey,
            $variable,
        ));
    }
}
