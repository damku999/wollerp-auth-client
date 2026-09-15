<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Support;

/**
 * RFC 7515 §2 base64url. Shared by the token verifier and the JWKS parser so
 * there is exactly one implementation of the strictness rules.
 */
final class Base64Url
{
    public static function encode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    /**
     * Strict: rejects padding, whitespace and the standard-base64 alphabet.
     * Returns null rather than throwing so callers choose their own exception.
     */
    public static function decode(string $input): ?string
    {
        if ($input === '' || preg_match('/^[A-Za-z0-9_-]+$/', $input) !== 1) {
            return null;
        }

        $remainder = strlen($input) % 4;

        if ($remainder === 1) {
            return null;
        }

        if ($remainder !== 0) {
            $input .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($input, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
