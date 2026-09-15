<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Exceptions;

use LogicException;

/**
 * CONTRACT §4: "Writes are permitted only from the synchroniser. Enforce with a
 * model guard that throws, not a code-review convention."
 *
 * This is a programming error, not a request error, so it deliberately does NOT
 * extend WollerpAuthException — it must not be swallowed by an auth catch block
 * and turned into a 401.
 */
final class MirrorWriteForbiddenException extends LogicException
{
    public static function for(string $operation, string $model): self
    {
        return new self(sprintf(
            '%s is a read-only projection of the auth server (CONTRACT §4). '
            .'Refusing to %s it. Writes may only originate from '
            .'Wollerp\AuthClient\Mirror\MirrorSynchroniser.',
            $model,
            $operation
        ));
    }
}
