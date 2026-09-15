<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Wollerp\AuthClient\Exceptions\InvalidTokenException;
use Wollerp\AuthClient\Exceptions\WollerpAuthException;
use Wollerp\AuthClient\Mirror\MirrorSynchroniser;
use Wollerp\AuthClient\Revocation\DenylistChecker;
use Wollerp\AuthClient\Token\Claims;
use Wollerp\AuthClient\Token\TokenValidator;

/**
 * Registered as the `wollerp` driver so consumers write `auth:wollerp`.
 *
 * Holds the request pipeline for layers 1 and 2 plus the mirror upsert, because
 * `auth:wollerp` has to work on its own — a product must not have to remember
 * to stack a second middleware before the guard becomes real. The Authenticate
 * middleware drives this class rather than duplicating it.
 *
 * user() swallows failures and returns null, as the Guard contract requires.
 * authenticateRequest() throws. Use the throwing one when you need the reason.
 */
final class TokenGuard implements Guard
{
    private ?Authenticatable $user = null;

    private ?Claims $claims = null;

    private bool $attempted = false;

    public function __construct(
        private readonly TokenValidator $validator,
        private readonly DenylistChecker $denylist,
        private readonly MirrorSynchroniser $mirror,
        private Request $request,
    ) {}

    /**
     * The full validation pipeline of CONTRACT §2, in order.
     *
     * @throws WollerpAuthException
     */
    public function authenticateRequest(?Request $request = null): Claims
    {
        $request ??= $this->request;

        $token = $request->bearerToken();

        if ($token === null || $token === '') {
            throw InvalidTokenException::missing();
        }

        // LAYER 1 — cryptographic, offline.
        $claims = $this->validator->validate($token);

        // LAYER 2 — revocation, one indexed local query.
        $this->denylist->assertNotRevoked($claims);

        // CONTRACT §4 layer 1 — token-driven mirror upsert, only when `ver` drifted.
        $this->mirror->syncFromClaims($claims);

        $this->claims = $claims;
        $this->user = $this->resolveUser($claims);
        $this->attempted = true;

        return $claims;
    }

    public function claims(): ?Claims
    {
        $this->user();

        return $this->claims;
    }

    public function user(): ?Authenticatable
    {
        if ($this->attempted) {
            return $this->user;
        }

        $this->attempted = true;

        try {
            $this->authenticateRequest();
        } catch (WollerpAuthException) {
            $this->user = null;
            $this->claims = null;
        }

        return $this->user;
    }

    public function check(): bool
    {
        return $this->user() !== null || $this->claims !== null;
    }

    public function guest(): bool
    {
        return ! $this->check();
    }

    public function id(): int|string|null
    {
        return $this->user()?->getAuthIdentifier();
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        $token = $credentials['token'] ?? $credentials['jwt'] ?? null;

        if (! is_string($token) || $token === '') {
            return false;
        }

        $claims = $this->validator->tryValidate($token);

        return $claims !== null && ! $this->denylist->isRevoked($claims);
    }

    public function hasUser(): bool
    {
        return $this->user !== null;
    }

    public function setUser(Authenticatable $user): static
    {
        $this->user = $user;
        $this->attempted = true;

        return $this;
    }

    public function setRequest(Request $request): static
    {
        $this->request = $request;
        $this->user = null;
        $this->claims = null;
        $this->attempted = false;

        return $this;
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * The mirror row is the user. It exists by the time we get here — the
     * upsert above either found it or created it — unless the mirror is
     * switched off, in which case the product gets claims but no user model.
     */
    private function resolveUser(Claims $claims): ?Authenticatable
    {
        if (! $this->mirror->enabled()) {
            return null;
        }

        $model = $this->mirror->find($claims->uid());

        return $model instanceof Authenticatable ? $model : null;
    }
}
