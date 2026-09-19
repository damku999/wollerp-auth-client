<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use LogicException;
use Symfony\Component\HttpFoundation\Response;
use Wollerp\AuthClient\Exceptions\WollerpAuthException;
use Wollerp\AuthClient\Guard\TokenGuard;
use Wollerp\AuthClient\Token\Claims;

/**
 * Alias: `wollerp.auth`.
 *
 * Runs CONTRACT §2 layers 1 and 2 and then the §4 mirror upsert, by driving the
 * `wollerp` guard, and answers each failure with the status the exception
 * carries: 401 with an RFC 6750 challenge for a bad token, **503 with
 * `Retry-After`** for `jwks_unavailable` / `jwks_unusable`. That split is the
 * reason to prefer this alias over `auth:wollerp` — Laravel's own Authenticate
 * sees only `check() === false` and answers 401 for an outage on our side.
 *
 * LAYER 3 — profile context, subscription, permission — is explicitly NOT here.
 * That is product-owned and resolved from the product's own database on every
 * request. This middleware answers "who is this", nothing else.
 */
final class Authenticate
{
    public const CLAIMS_ATTRIBUTE = 'wollerp_claims';

    public function __construct(
        private readonly AuthFactory $auth,
        private readonly string $guardName = 'wollerp',
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $guard = $this->auth->guard($this->guardName);

        if (! $guard instanceof TokenGuard) {
            throw new LogicException(sprintf(
                'Guard [%s] is a %s, not a Wollerp TokenGuard. Add '
                ."'%s' => ['driver' => 'wollerp'] to config/auth.php.",
                $this->guardName,
                $guard::class,
                $this->guardName,
            ));
        }

        try {
            $claims = $guard->authenticateRequest($request);
        } catch (WollerpAuthException $exception) {
            return $this->deny($exception);
        }

        $request->attributes->set(self::CLAIMS_ATTRIBUTE, $claims);
        $request->setUserResolver(static fn () => $guard->user());

        return $next($request);
    }

    /**
     * Convenience for product code: the verified claims for this request.
     */
    public static function claims(Request $request): ?Claims
    {
        $claims = $request->attributes->get(self::CLAIMS_ATTRIBUTE);

        return $claims instanceof Claims ? $claims : null;
    }

    /**
     * RFC 6750 §3. The reason is coarse and fixed — enough for an integrator to
     * debug, not enough to tell an attacker which check they nearly passed.
     *
     * Not every failure here is the caller's fault. A JWKS outage on a cold
     * cache is a 503 (CONTRACT §3), and it must not be dressed up as a bearer
     * challenge: a client that retries a 401 by re-authenticating would send a
     * user back through login for an outage on our side, and the event would
     * hide inside the 401 noise instead of showing on an availability board.
     */
    private function deny(WollerpAuthException $exception): JsonResponse
    {
        $status = $exception->status();

        if ($status !== 401) {
            return new JsonResponse(
                [
                    'success' => false,
                    'error' => 'authentication_unavailable',
                    'reason' => $exception->reason(),
                ],
                $status,
                ['Retry-After' => '30'],
            );
        }

        return new JsonResponse(
            [
                'success' => false,
                'error' => 'unauthenticated',
                'reason' => $exception->reason(),
            ],
            $status,
            [
                'WWW-Authenticate' => sprintf(
                    'Bearer realm="wollerp", error="invalid_token", error_description="%s"',
                    $exception->reason()
                ),
            ],
        );
    }
}
