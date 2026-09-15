<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Response;
use Wollerp\AuthClient\Exceptions\InvalidServiceSignatureException;
use Wollerp\AuthClient\Hmac\Signer;
use Wollerp\AuthClient\Hmac\Verifier;

/**
 * Alias: `wollerp.hmac`. Put it on every `/api/v1/internal/*` route.
 *
 * CONTRACT §5: "Every internal call carries BOTH controls: IP allowlist *and*
 * HMAC signature." The allowlist is checked here too rather than being left
 * entirely to the load balancer, because the balancer config lives in a
 * different repo with a different review process and drifts silently. Leave
 * `hmac.allowed_ips` empty only if you have deliberately decided the network
 * layer owns it.
 *
 * `$request->getContent()` is the raw body — read before any JSON decode, as
 * required. Note that Laravel buffers it, so reading it here does not consume
 * the stream for the controller.
 */
final class VerifyHmacSignature
{
    public const PROJECT_ATTRIBUTE = 'wollerp_calling_project';

    /**
     * @param  list<string>  $allowedIps  CIDR or plain addresses; empty disables the check.
     */
    public function __construct(
        private readonly Verifier $verifier,
        private readonly array $allowedIps = [],
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        try {
            $this->assertIpAllowed($request);

            $this->verifier->verify(
                $request->header(Signer::PROJECT_HEADER),
                $request->header(Signer::TIMESTAMP_HEADER),
                $request->header(Signer::SIGNATURE_HEADER),
                $request->getContent(),
            );
        } catch (InvalidServiceSignatureException $exception) {
            return new JsonResponse(
                [
                    'success' => false,
                    'error' => 'invalid_service_signature',
                    'reason' => $exception->reason(),
                ],
                401,
            );
        }

        $request->attributes->set(
            self::PROJECT_ATTRIBUTE,
            (string) $request->header(Signer::PROJECT_HEADER)
        );

        return $next($request);
    }

    private function assertIpAllowed(Request $request): void
    {
        if ($this->allowedIps === []) {
            return;
        }

        $ip = $request->ip();

        if ($ip === null || ! IpUtils::checkIp($ip, $this->allowedIps)) {
            throw InvalidServiceSignatureException::ipNotAllowed();
        }
    }
}
