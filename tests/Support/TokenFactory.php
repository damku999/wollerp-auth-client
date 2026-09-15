<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Tests\Support;

use OpenSSLAsymmetricKey;
use RuntimeException;
use Wollerp\AuthClient\Support\Base64Url;

/**
 * Generates a real RSA keypair at runtime and mints tokens with it, so the
 * conformance suite is entirely self-contained: no fixtures, no checked-in keys,
 * no dependency on the auth server being reachable.
 *
 * It can also mint the tokens an attacker would try — `alg: none` and an HS256
 * token signed with the RSA PUBLIC key — which is the whole point of the suite.
 */
final class TokenFactory
{
    public const ISSUER = 'https://auth.wollerp.lumicorelabs.com';

    public const AUDIENCE = 'cc';

    public const JWKS_URL = self::ISSUER.'/.well-known/jwks.json';

    public const SUB = '01JBX7K2QF8N3M5P9R4T6V8W0Y';

    public const UID = 4217;

    public const JTI = '01JBY5M8P2Q4R6S8T0V2W4X6Y8';

    public const SID = '01JBZ3K5M7N9P1Q3R5S7T9V1W3';

    private static ?self $shared = null;

    public readonly OpenSSLAsymmetricKey $privateKey;

    public readonly string $publicKeyPem;

    public readonly string $modulus;

    public readonly string $exponent;

    public function __construct(public readonly string $kid = 'test-2026-09')
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            throw new RuntimeException(
                'openssl_pkey_new() failed: '.(openssl_error_string() ?: 'unknown error').'. '
                .'On Windows this usually means OPENSSL_CONF is not set for the CLI php.ini.'
            );
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false || ! isset($details['rsa']['n'], $details['rsa']['e'], $details['key'])) {
            throw new RuntimeException('Could not read the generated RSA key details.');
        }

        $this->privateKey = $key;
        $this->publicKeyPem = (string) $details['key'];
        $this->modulus = (string) $details['rsa']['n'];
        $this->exponent = (string) $details['rsa']['e'];
    }

    /**
     * Key generation is the slowest thing in the suite; one shared keypair is
     * enough for everything except the unknown-kid case.
     */
    public static function shared(): self
    {
        return self::$shared ??= new self;
    }

    /**
     * @return array<string, string>
     */
    public function jwk(): array
    {
        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $this->kid,
            'n' => Base64Url::encode($this->modulus),
            'e' => Base64Url::encode($this->exponent),
        ];
    }

    /**
     * The CONTRACT §1 example payload, with the ability to override any claim
     * or drop one by passing null through $remove.
     *
     * @param  array<string, mixed>  $overrides
     * @param  list<string>  $remove
     * @return array<string, mixed>
     */
    public function payload(array $overrides = [], array $remove = []): array
    {
        $now = time();

        $payload = [
            'iss' => self::ISSUER,
            'sub' => self::SUB,
            'uid' => self::UID,
            'aud' => [self::AUDIENCE],
            'exp' => $now + 900,
            'iat' => $now,
            'nbf' => $now,
            'jti' => self::JTI,
            'sid' => self::SID,
            'ver' => 7,
            'email' => 'user@example.com',
            'name' => 'Jane Smith',
            'email_verified' => true,
            'amr' => ['pwd', 'otp'],
            'auth_time' => $now,
        ];

        foreach ($remove as $claim) {
            unset($payload[$claim]);
        }

        return array_merge($payload, $overrides);
    }

    /**
     * A genuine RS256 token.
     *
     * @param  array<string, mixed>  $payload
     * @param  array<string, mixed>  $headerOverrides
     */
    public function sign(array $payload, array $headerOverrides = []): string
    {
        $header = array_merge(['typ' => 'JWT', 'alg' => 'RS256', 'kid' => $this->kid], $headerOverrides);

        $input = $this->encode($header).'.'.$this->encode($payload);

        $signature = '';

        if (openssl_sign($input, $signature, $this->privateKey, OPENSSL_ALGO_SHA256) === false) {
            throw new RuntimeException('openssl_sign() failed.');
        }

        return $input.'.'.Base64Url::encode($signature);
    }

    /**
     * `alg: none` — the oldest bypass there is. A verifier that reads the
     * algorithm from the header accepts this with no key at all.
     *
     * @param  array<string, mixed>  $payload
     */
    public function algNone(array $payload, string $signature = ''): string
    {
        $header = ['typ' => 'JWT', 'alg' => 'none', 'kid' => $this->kid];

        return $this->encode($header).'.'.$this->encode($payload).'.'.$signature;
    }

    /**
     * HS256, keyed with the RSA PUBLIC key.
     *
     * This is the algorithm-confusion attack. The public key is published at
     * the JWKS endpoint for anyone to fetch, so if the verifier lets the header
     * choose the algorithm, the attacker holds the "secret" and can mint any
     * token they like for any user.
     *
     * @param  array<string, mixed>  $payload
     */
    public function hs256WithPublicKey(array $payload, ?string $algorithmLabel = 'HS256'): string
    {
        $header = ['typ' => 'JWT', 'alg' => $algorithmLabel, 'kid' => $this->kid];

        $input = $this->encode($header).'.'.$this->encode($payload);

        return $input.'.'.Base64Url::encode(
            hash_hmac('sha256', $input, $this->publicKeyPem, true)
        );
    }

    /**
     * Flip the last byte of the signature. Everything else stays valid.
     */
    public function tamperSignature(string $token): string
    {
        $segments = explode('.', $token);
        $signature = Base64Url::decode($segments[2]);

        if ($signature === null || $signature === '') {
            throw new RuntimeException('Cannot tamper with an unsigned token.');
        }

        $signature[strlen($signature) - 1] = chr(ord($signature[strlen($signature) - 1]) ^ 0xFF);
        $segments[2] = Base64Url::encode($signature);

        return implode('.', $segments);
    }

    /**
     * Swap the payload for a different one while keeping the original
     * signature — the naive "just edit the claims" attempt.
     *
     * @param  array<string, mixed>  $payload
     */
    public function tamperPayload(string $token, array $payload): string
    {
        $segments = explode('.', $token);
        $segments[1] = $this->encode($payload);

        return implode('.', $segments);
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function encode(array $data): string
    {
        return Base64Url::encode(
            json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)
        );
    }
}
