<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Support;

use JsonException;

/**
 * Parses the `WOLLERP_AUTH_BUNDLED_JWKS` environment value into the array shape
 * `jwks.bundled_keys` expects.
 *
 * ── Why an env var is safe here ──────────────────────────────────────────────
 * Bundled keys look like the most dangerous thing to make environment-driven,
 * and they are not, for three reasons:
 *
 * 1. Anyone who can write the environment already owns authentication outright:
 *    `WOLLERP_AUTH_ISSUER` and `WOLLERP_AUTH_JWKS_URL` are already env-driven,
 *    and repointing either is a far easier forgery than crafting a JWK. This
 *    adds no trust boundary that did not already exist.
 * 2. A bundled key is not a bypass of anything. It is consulted only when the
 *    JWKS endpoint is unreachable AND nothing is cached, and it still has to
 *    match the token's `kid` and then actually verify the RS256 signature.
 *    JwksClient::toPem() additionally drops any entry that is not RSA, not
 *    RS256, not `use: sig`, under 2048 bits, or does not parse.
 * 3. It fails closed and quietly. An unparsable value yields an empty array,
 *    which is exactly today's shipped default — a cold-cache JWKS outage stays
 *    a 503. It must never throw: this runs inside a config file, and a config
 *    file that throws takes every `php artisan` command down with it.
 *
 * ── Accepted forms ───────────────────────────────────────────────────────────
 * A full JWKS document, a bare list of JWKs, or a single JWK object — each
 * either as raw JSON or base64-encoded. Base64 exists because a JWKS document
 * is full of `"`, `{` and `=`, which is miserable to quote correctly in a
 * `.env` file and is the kind of thing that silently half-works:
 *
 *   WOLLERP_AUTH_BUNDLED_JWKS="$(curl -s https://auth…/.well-known/jwks.json | base64 -w0)"
 */
final class BundledKeys
{
    /**
     * @return list<array<string, mixed>>
     */
    public static function fromEnv(mixed $value): array
    {
        if (is_array($value)) {
            return self::normalise($value);
        }

        if (! is_string($value)) {
            return [];
        }

        $value = trim($value);

        if ($value === '') {
            return [];
        }

        $decoded = self::decodeJson($value);

        if ($decoded === null) {
            // Not JSON. Try base64 before giving up — the documented way of
            // getting a JWKS document through a .env file in one piece.
            $binary = base64_decode(strtr($value, '-_', '+/'), true);

            if ($binary === false || $binary === '') {
                return [];
            }

            $decoded = self::decodeJson(trim($binary));
        }

        return $decoded === null ? [] : self::normalise($decoded);
    }

    /**
     * @return array<mixed>|null
     */
    private static function decodeJson(string $json): ?array
    {
        if ($json === '' || ($json[0] !== '{' && $json[0] !== '[')) {
            return null;
        }

        try {
            $decoded = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Accepts `{"keys": [...]}`, `[...]`, or a single `{...}` JWK.
     *
     * @param  array<mixed>  $decoded
     * @return list<array<string, mixed>>
     */
    private static function normalise(array $decoded): array
    {
        if (isset($decoded['keys']) && is_array($decoded['keys'])) {
            $decoded = $decoded['keys'];
        } elseif (isset($decoded['kty'])) {
            $decoded = [$decoded];
        }

        $keys = [];

        foreach ($decoded as $jwk) {
            // Every entry is handed to JwksClient::toPem() later, which is the
            // real gate. All that matters here is that the shape is a map.
            if (is_array($jwk) && $jwk !== [] && ! array_is_list($jwk)) {
                /** @var array<string, mixed> $jwk */
                $keys[] = $jwk;
            }
        }

        return $keys;
    }
}
