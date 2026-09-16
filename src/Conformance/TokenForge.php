<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Conformance;

use OpenSSLAsymmetricKey;
use RuntimeException;
use Wollerp\AuthClient\Support\Base64Url;

/**
 * Generates a throwaway 2048-bit RSA keypair at runtime and mints tokens with
 * it — both genuine ones and the exact forgeries an attacker would try.
 *
 * This lives in `src/`, not `tests/`, on purpose. A consumer's Composer install
 * never loads this package's `autoload-dev`, so anything the conformance suite
 * needs in order to run inside a product backend has to be shipped. It carries
 * no test-framework dependency and never touches the network, the filesystem or
 * the auth server.
 *
 * Nothing minted here is ever trusted by anything: the keypair exists for the
 * duration of one PHP process and the public half is only ever handed to a
 * TokenValidator that the conformance run constructed for itself.
 */
class TokenForge
{
    public readonly OpenSSLAsymmetricKey $privateKey;

    public readonly string $publicKeyPem;

    public readonly string $modulus;

    public readonly string $exponent;

    public function __construct(
        public readonly string $issuer,
        public readonly string $audience,
        public readonly string $kid = 'wollerp-conformance-ephemeral',
    ) {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            throw new RuntimeException(
                'openssl_pkey_new() failed: '.(openssl_error_string() ?: 'unknown error').'. '
                .'On Windows this usually means OPENSSL_CONF is not set for the CLI php.ini; '
                .'point it at your PHP build\'s extras/ssl/openssl.cnf.'
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
     * The public half, as the auth server would publish it.
     *
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
     * The CONTRACT §1 payload, with the ability to override any claim or drop
     * one by naming it in $remove.
     *
     * @param  array<string, mixed>  $overrides
     * @param  list<string>  $remove
     * @return array<string, mixed>
     */
    public function payload(array $overrides = [], array $remove = []): array
    {
        $payload = $this->defaultPayload(time());

        foreach ($remove as $claim) {
            unset($payload[$claim]);
        }

        return array_merge($payload, $overrides);
    }

    /**
     * Deliberately unmistakable identifiers. If one of these ever turns up in a
     * production log or a mirror row, something ran a conformance check against
     * live state and that is worth finding immediately.
     *
     * @return array<string, mixed>
     */
    protected function defaultPayload(int $now): array
    {
        return [
            'iss' => $this->issuer,
            'sub' => '01CONFORMANCE0000000000000',
            'uid' => 999000001,
            'aud' => [$this->audience],
            'exp' => $now + 900,
            'iat' => $now,
            'nbf' => $now,
            'jti' => '01CONFORMANCEJTI0000000000',
            'sid' => '01CONFORMANCESID0000000000',
            'ver' => 1,
            'email' => 'conformance@invalid',
            'name' => 'Conformance Probe',
            'email_verified' => true,
            'amr' => ['pwd'],
            'auth_time' => $now,
        ];
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
     * The algorithm-confusion attack. The public key is published at the JWKS
     * endpoint for anyone to fetch, so if the verifier lets the header choose
     * the algorithm, the attacker holds the "secret" and can mint any token
     * they like for any user.
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
     * Re-encode the header without `alg` at all, keeping a real RS256
     * signature over the original input.
     *
     * @param  array<string, mixed>  $payload
     */
    public function withoutAlgHeader(array $payload): string
    {
        $token = $this->sign($payload);

        [, $body, $signature] = explode('.', $token);

        $header = $this->encode(['typ' => 'JWT', 'kid' => $this->kid]);

        return "{$header}.{$body}.{$signature}";
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
    protected function encode(array $data): string
    {
        return Base64Url::encode(
            json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)
        );
    }
}
