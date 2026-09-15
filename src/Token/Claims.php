<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Token;

use JsonSerializable;

/**
 * Typed, read-only view of a token payload that has already passed
 * TokenValidator. CONTRACT §1.
 *
 * Nothing in here validates anything — by the time you hold a Claims instance
 * the signature, issuer, audience, expiry and required-claim checks have all
 * passed. Never construct one from unverified input.
 *
 * Deliberately absent, per CONTRACT §1: roles, permissions, subscription, plan,
 * modules, active_profile_type, company_id, client_id, professional_id. Those
 * are answered by the product database on every request, not cached in a token.
 */
final readonly class Claims implements JsonSerializable
{
    /**
     * @param  array<string, mixed>  $payload
     */
    public function __construct(private array $payload) {}

    /** Global user identity (ULID, 26 chars). */
    public function sub(): string
    {
        return (string) ($this->payload['sub'] ?? '');
    }

    /** Legacy integer id — preserves existing created_by joins. */
    public function uid(): int
    {
        return (int) ($this->payload['uid'] ?? 0);
    }

    /**
     * ALWAYS an array, even when the issuer sent a bare string.
     *
     * @return list<string>
     */
    public function aud(): array
    {
        $aud = $this->payload['aud'] ?? [];

        if (! is_array($aud)) {
            return [(string) $aud];
        }

        return array_values(array_map(static fn (mixed $v): string => (string) $v, $aud));
    }

    public function iss(): string
    {
        return (string) ($this->payload['iss'] ?? '');
    }

    /** Session / refresh-token family id. Denylist target for session revocation. */
    public function sid(): string
    {
        return (string) ($this->payload['sid'] ?? '');
    }

    /** Per-token id. Denylist target for single-token revocation. */
    public function jti(): string
    {
        return (string) ($this->payload['jti'] ?? '');
    }

    /** User record version. Drives the mirror upsert (CONTRACT §4). */
    public function ver(): int
    {
        return (int) ($this->payload['ver'] ?? 0);
    }

    public function email(): ?string
    {
        $email = $this->payload['email'] ?? null;

        return is_string($email) && $email !== '' ? $email : null;
    }

    public function name(): ?string
    {
        $name = $this->payload['name'] ?? null;

        return is_string($name) && $name !== '' ? $name : null;
    }

    /**
     * Authentication methods used: pwd, otp, totp, recovery.
     *
     * @return list<string>
     */
    public function amr(): array
    {
        $amr = $this->payload['amr'] ?? [];

        if (! is_array($amr)) {
            return [];
        }

        return array_values(array_map(static fn (mixed $v): string => (string) $v, $amr));
    }

    /** Unix time the user actually authenticated. Null when the issuer omitted it. */
    public function authTime(): ?int
    {
        $authTime = $this->payload['auth_time'] ?? null;

        return is_numeric($authTime) ? (int) $authTime : null;
    }

    public function emailVerified(): bool
    {
        return filter_var(
            $this->payload['email_verified'] ?? false,
            FILTER_VALIDATE_BOOL
        );
    }

    public function exp(): int
    {
        return (int) ($this->payload['exp'] ?? 0);
    }

    public function iat(): ?int
    {
        $iat = $this->payload['iat'] ?? null;

        return is_numeric($iat) ? (int) $iat : null;
    }

    /**
     * Offline re-auth check for sensitive operations (change password, rotate a
     * payout account, delete a tenant): "did this person prove who they are in
     * the last N seconds, or are they just riding a 15-minute access token?"
     *
     * Returns false when the issuer omitted auth_time — fail closed.
     */
    public function authenticatedWithin(int $seconds, ?int $now = null): bool
    {
        $authTime = $this->authTime();

        if ($authTime === null || $seconds < 0) {
            return false;
        }

        $now ??= time();

        return $authTime <= $now && ($now - $authTime) <= $seconds;
    }

    public function authenticatedWith(string $method): bool
    {
        return in_array($method, $this->amr(), true);
    }

    public function has(string $claim): bool
    {
        return array_key_exists($claim, $this->payload);
    }

    public function get(string $claim, mixed $default = null): mixed
    {
        return $this->payload[$claim] ?? $default;
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->payload;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->payload;
    }
}
