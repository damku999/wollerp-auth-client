<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Tests\Support;

use Wollerp\AuthClient\Conformance\TokenForge;

/**
 * The package's own test harness: a TokenForge pinned to fixed issuer, audience
 * and identity values so tests can assert on exact claims.
 *
 * The minting itself — the real keypair, `alg: none`, the HS256-signed-with-the-
 * RSA-public-key forgery, signature and payload tampering — lives in TokenForge
 * under `src/`, because the shipped conformance suite needs exactly the same
 * attack tokens and a consumer never loads this package's `autoload-dev`.
 *
 * Keeping one implementation matters more here than usual: if these two drifted,
 * the forgeries the package tests itself against would stop being the forgeries
 * it tests a product against, and only one of the two would be the real gate.
 */
final class TokenFactory extends TokenForge
{
    public const ISSUER = 'https://auth.wollerp.lumicorelabs.com';

    public const AUDIENCE = 'cc';

    public const JWKS_URL = self::ISSUER.'/.well-known/jwks.json';

    public const SUB = '01JBX7K2QF8N3M5P9R4T6V8W0Y';

    public const UID = 4217;

    public const JTI = '01JBY5M8P2Q4R6S8T0V2W4X6Y8';

    public const SID = '01JBZ3K5M7N9P1Q3R5S7T9V1W3';

    private static ?self $shared = null;

    public function __construct(string $kid = 'test-2026-09')
    {
        parent::__construct(self::ISSUER, self::AUDIENCE, $kid);
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
     * The CONTRACT §1 example payload.
     *
     * @return array<string, mixed>
     */
    protected function defaultPayload(int $now): array
    {
        return [
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
    }
}
