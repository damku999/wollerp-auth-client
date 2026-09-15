<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Token;

use Closure;
use InvalidArgumentException;
use JsonException;
use Wollerp\AuthClient\Exceptions\InvalidTokenException;
use Wollerp\AuthClient\Jwks\JwksClient;
use Wollerp\AuthClient\Support\Base64Url;

/**
 * LAYER 1 of CONTRACT §2 — cryptographic validation, fully offline.
 *
 *   1. decode header, read `kid`
 *   2. resolve `kid` via the JWKS cache
 *   3. PIN alg = RS256                       ◄ total bypass if missed
 *   4. verify the RSA signature
 *   5. exp / nbf / iat, leeway <= 60 s
 *   6. iss exact string match
 *   7. aud contains this service's slug
 *
 * On the pinning, because it is the whole ballgame: the algorithm is a property
 * of the VERIFIER, not of the token. This class hard-codes OPENSSL_ALGO_SHA256
 * and openssl_verify() with an RSA public key. The header's `alg` is read for
 * exactly one purpose — to reject anything that is not the literal string
 * "RS256" — and is never used to select a routine or a key type. `alg: none`
 * and an HS256 token signed with the RSA public key (which is published at the
 * JWKS endpoint for anyone to fetch) are both complete authentication bypasses
 * against a verifier that trusts the header.
 *
 * There is intentionally no configuration option for the algorithm.
 */
final class TokenValidator
{
    public const ALGORITHM = 'RS256';

    public const DEFAULT_LEEWAY = 60;

    /** CONTRACT §2: "Clock leeway <= 60 seconds. Hosts run NTP." */
    public const MAX_LEEWAY = 60;

    /**
     * Claims without which the rest of the platform cannot function:
     * identity (sub/uid), revocation targets (jti/sid), mirror version (ver).
     */
    private const REQUIRED_CLAIMS = ['iss', 'aud', 'exp', 'sub', 'uid', 'jti', 'sid', 'ver'];

    public readonly int $leeway;

    /**
     * @param  Closure(): int|null  $clock  Injected for testability; defaults to time().
     */
    public function __construct(
        private readonly JwksClient $jwks,
        private readonly string $issuer,
        private readonly string $audience,
        int $leeway = self::DEFAULT_LEEWAY,
        private readonly int $maxTokenLength = 8192,
        private readonly ?Closure $clock = null,
    ) {
        // Fail closed on an unconfigured identity. CONTRACT §7 makes the product
        // registry open, so this package cannot ship a default slug — and an
        // empty issuer or audience would otherwise turn every check below into
        // "compare against nothing", which is how a Brick Case token ends up
        // opening a Coms Coupler session.
        if ($issuer === '') {
            throw new InvalidArgumentException(
                'wollerp-auth.issuer is not configured; set WOLLERP_AUTH_ISSUER.'
            );
        }

        if ($audience === '') {
            throw new InvalidArgumentException(
                'wollerp-auth.audience is not configured; set WOLLERP_SERVICE_SLUG to this '
                ."product's registry slug (CONTRACT §7)."
            );
        }

        // Clamped here rather than validated at boot: a bad config value must
        // degrade to the safe maximum, never widen the window.
        $this->leeway = max(0, min(self::MAX_LEEWAY, $leeway));
    }

    /**
     * @throws InvalidTokenException
     * @throws \Wollerp\AuthClient\Exceptions\JwksException
     */
    public function validate(string $token): Claims
    {
        $token = trim($token);

        if ($token === '') {
            throw InvalidTokenException::missing();
        }

        if (strlen($token) > $this->maxTokenLength) {
            throw InvalidTokenException::tooLarge($this->maxTokenLength);
        }

        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            throw InvalidTokenException::malformed(
                'A compact JWS has exactly three segments; '.count($segments).' presented.'
            );
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $segments;

        $header = $this->decodeSegment($encodedHeader, 'header');

        // ── Step 3. Pin the algorithm. Nothing below this line may vary by it. ──
        $algorithm = $header['alg'] ?? null;

        if (! is_string($algorithm) || ! hash_equals(self::ALGORITHM, $algorithm)) {
            throw InvalidTokenException::unsupportedAlgorithm(
                is_string($algorithm) ? $algorithm : gettype($algorithm)
            );
        }

        $kid = $header['kid'] ?? null;

        if (! is_string($kid) || $kid === '') {
            throw InvalidTokenException::missingKeyId();
        }

        // ── Steps 2 + 4. Resolve the key and verify the RSA signature. ──
        $signature = Base64Url::decode($encodedSignature);

        if ($signature === null) {
            throw InvalidTokenException::malformed('Signature segment is not valid base64url.');
        }

        $publicKey = $this->jwks->publicKeyFor($kid);

        $verified = openssl_verify(
            $encodedHeader.'.'.$encodedPayload,
            $signature,
            $publicKey,
            OPENSSL_ALGO_SHA256,
        );

        if ($verified !== 1) {
            throw InvalidTokenException::signatureMismatch();
        }

        $payload = $this->decodeSegment($encodedPayload, 'payload');

        $this->assertRequiredClaims($payload);
        $this->assertTemporalClaims($payload);
        $this->assertIssuer($payload);
        $this->assertAudience($payload);

        return new Claims($payload);
    }

    /**
     * Non-throwing variant for code paths where an anonymous fallback is valid.
     */
    public function tryValidate(string $token): ?Claims
    {
        try {
            return $this->validate($token);
        } catch (InvalidTokenException) {
            return null;
        }
    }

    public function audience(): string
    {
        return $this->audience;
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeSegment(string $segment, string $label): array
    {
        $json = Base64Url::decode($segment);

        if ($json === null) {
            throw InvalidTokenException::malformed("Token {$label} is not valid base64url.");
        }

        try {
            $decoded = json_decode($json, true, 16, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (JsonException) {
            throw InvalidTokenException::malformed("Token {$label} is not valid JSON.");
        }

        if (! is_array($decoded) || array_is_list($decoded)) {
            throw InvalidTokenException::malformed("Token {$label} is not a JSON object.");
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function assertRequiredClaims(array $payload): void
    {
        foreach (self::REQUIRED_CLAIMS as $claim) {
            if (! array_key_exists($claim, $payload) || $payload[$claim] === null || $payload[$claim] === '') {
                throw InvalidTokenException::missingClaim($claim);
            }
        }

        foreach (['sub', 'jti', 'sid'] as $claim) {
            if (! is_string($payload[$claim])) {
                throw InvalidTokenException::missingClaim($claim);
            }
        }

        foreach (['uid', 'ver'] as $claim) {
            if (! is_int($payload[$claim]) && ! (is_string($payload[$claim]) && ctype_digit($payload[$claim]))) {
                throw InvalidTokenException::missingClaim($claim);
            }
        }

        if ((int) $payload['uid'] <= 0) {
            throw InvalidTokenException::missingClaim('uid');
        }
    }

    /**
     * Step 5. exp / nbf / iat.
     *
     * @param  array<string, mixed>  $payload
     */
    private function assertTemporalClaims(array $payload): void
    {
        $now = $this->now();

        if (! is_numeric($payload['exp'])) {
            throw InvalidTokenException::missingClaim('exp');
        }

        if ($now > ((int) $payload['exp'] + $this->leeway)) {
            throw InvalidTokenException::expired();
        }

        if (isset($payload['nbf'])) {
            if (! is_numeric($payload['nbf'])) {
                throw InvalidTokenException::missingClaim('nbf');
            }

            if (($now + $this->leeway) < (int) $payload['nbf']) {
                throw InvalidTokenException::notYetValid();
            }
        }

        if (isset($payload['iat'])) {
            if (! is_numeric($payload['iat'])) {
                throw InvalidTokenException::missingClaim('iat');
            }

            if (($now + $this->leeway) < (int) $payload['iat']) {
                throw InvalidTokenException::issuedInFuture();
            }
        }
    }

    /**
     * Step 6. Exact match only. Never prefix or suffix matched — an issuer
     * check of `str_starts_with($iss, $expected)` is satisfied by
     * "https://auth.wollerp.lumicorelabs.com.attacker.example".
     *
     * @param  array<string, mixed>  $payload
     */
    private function assertIssuer(array $payload): void
    {
        $issuer = $payload['iss'];

        if (! is_string($issuer) || ! hash_equals($this->issuer, $issuer)) {
            throw InvalidTokenException::issuerMismatch();
        }
    }

    /**
     * Step 7. CONTRACT §1 says `aud` is always an array. A bare string is
     * accepted and normalised rather than rejected: RFC 7519 permits it, and
     * membership is still checked exactly, so accepting it costs nothing and
     * refusing it would turn an issuer-side formatting change into an estate
     * wide outage.
     *
     * @param  array<string, mixed>  $payload
     */
    private function assertAudience(array $payload): void
    {
        $audience = $payload['aud'];
        $audiences = is_array($audience) ? $audience : [$audience];

        foreach ($audiences as $candidate) {
            if (is_string($candidate) && hash_equals($this->audience, $candidate)) {
                return;
            }
        }

        throw InvalidTokenException::audienceMismatch();
    }

    private function now(): int
    {
        return $this->clock !== null ? ($this->clock)() : time();
    }
}
