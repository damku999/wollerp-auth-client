<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Jwks;

use Illuminate\Contracts\Cache\Repository;

/**
 * CONTRACT §3 — file driver, 6 h TTL, refetch on unknown kid.
 *
 * Two things here exist specifically so a JWKS outage is not an auth outage:
 *
 * 1. Every successful fetch is written twice: once under the 6 h working key,
 *    and once under a long-lived "last known good" key. When the endpoint is
 *    down at the moment the working copy expires, we keep serving the last set
 *    we saw rather than failing every request in the estate.
 * 2. Forced refetches (triggered by an unknown `kid`) are throttled. Without
 *    that, anyone can make us hammer the auth server by sending garbage kids.
 *
 * Values cached are `kid => PEM public key`, already converted and validated.
 */
final class JwksCache
{
    /** Last-known-good copy lives this many multiples of the working TTL. */
    private const STALE_MULTIPLIER = 28;

    public function __construct(
        private readonly Repository $cache,
        private readonly string $key = 'wollerp-auth:jwks',
        private readonly int $ttl = 21600,
        private readonly int $refetchCooldown = 60,
    ) {}

    /**
     * @return array<string, string>|null
     */
    public function keys(): ?array
    {
        $keys = $this->cache->get($this->key);

        return is_array($keys) && $keys !== [] ? $keys : null;
    }

    /**
     * The survival copy. Only consulted when a live fetch fails.
     *
     * @return array<string, string>|null
     */
    public function lastKnownGood(): ?array
    {
        $keys = $this->cache->get($this->staleKey());

        return is_array($keys) && $keys !== [] ? $keys : null;
    }

    /**
     * @param  array<string, string>  $keys
     */
    public function put(array $keys): void
    {
        if ($keys === []) {
            return;
        }

        $this->cache->put($this->key, $keys, $this->ttl);
        $this->cache->put($this->staleKey(), $keys, $this->ttl * self::STALE_MULTIPLIER);
    }

    /**
     * True at most once per cooldown window. Claims the slot as a side effect,
     * so callers must act on a true return.
     */
    public function claimRefetchSlot(): bool
    {
        if ($this->refetchCooldown <= 0) {
            return true;
        }

        return $this->cache->add($this->key.':refetch', true, $this->refetchCooldown);
    }

    public function flush(): void
    {
        $this->cache->forget($this->key);
        $this->cache->forget($this->key.':refetch');
    }

    private function staleKey(): string
    {
        return $this->key.':last-known-good';
    }
}
