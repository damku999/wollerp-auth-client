<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Hmac;

use Closure;
use Wollerp\AuthClient\Exceptions\InvalidServiceSignatureException;

/**
 * CONTRACT §5 — inbound half of the service plane.
 *
 * Three rules, all non-negotiable:
 *
 * - `|now - timestamp| <= 300`. Both directions: a future timestamp is as much
 *   a replay primitive as a past one.
 * - `hash_equals()`, never `==`. `==` is timing-variable, and PHP's type
 *   juggling on two numeric-looking strings (`'0e123' == '0e456'`) will
 *   occasionally just declare two different digests equal.
 * - MAC the RAW body, before any JSON decode.
 *
 * A distinct secret per service pair, so a compromised product cannot forge
 * calls that appear to come from a different one.
 */
final class Verifier
{
    public const DEFAULT_WINDOW = 300;

    /**
     * @param  array<string, string>  $secrets  project slug => shared secret
     * @param  Closure(): int|null  $clock
     */
    public function __construct(
        private readonly array $secrets,
        private readonly int $window = self::DEFAULT_WINDOW,
        private readonly ?Closure $clock = null,
    ) {}

    /**
     * @throws InvalidServiceSignatureException
     */
    public function verify(
        ?string $project,
        ?string $timestamp,
        ?string $signature,
        string $rawBody,
    ): void {
        if ($project === null || $project === '' || ! array_key_exists($project, $this->secrets)) {
            throw InvalidServiceSignatureException::unknownProject();
        }

        $secret = $this->secrets[$project];

        if ($secret === '') {
            throw InvalidServiceSignatureException::secretNotConfigured($project);
        }

        if ($timestamp === null || preg_match('/^\d{1,11}$/', $timestamp) !== 1) {
            throw InvalidServiceSignatureException::malformedTimestamp();
        }

        $now = $this->clock !== null ? ($this->clock)() : time();

        if (abs($now - (int) $timestamp) > $this->window) {
            throw InvalidServiceSignatureException::staleTimestamp($this->window);
        }

        if ($signature === null || $signature === '') {
            throw InvalidServiceSignatureException::mismatch();
        }

        $expected = 'sha256='.hash_hmac('sha256', $timestamp.'.'.$rawBody, $secret);

        if (! hash_equals($expected, $signature)) {
            throw InvalidServiceSignatureException::mismatch();
        }
    }

    public function knows(string $project): bool
    {
        return array_key_exists($project, $this->secrets) && $this->secrets[$project] !== '';
    }
}
