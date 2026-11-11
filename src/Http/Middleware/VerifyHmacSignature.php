<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Http\Middleware;

use Closure;
use Illuminate\Contracts\Cache\Repository as Cache;
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
        private readonly ?Cache $cache = null,
        private readonly int $window = Verifier::DEFAULT_WINDOW,
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

            $this->assertNotReplayed((string) $request->header(Signer::SIGNATURE_HEADER));
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

    /**
     * A valid signature is accepted ONCE. The signature covers only the
     * timestamp and body, so inside the window a captured call could otherwise
     * be replayed, or sent to a sibling endpoint taking the same body
     * (handles/confirm vs handles/release). Senders sign every attempt afresh,
     * so a legitimate retry never repeats a signature.
     *
     * A cache outage must not stop revocations reaching the product: the
     * replay check is skipped (and reported) rather than failing the call.
     */
    private function assertNotReplayed(string $signature): void
    {
        if ($this->cache === null) {
            return;
        }

        try {
            $first = $this->cache->add('wollerp-hmac-seen:'.hash('sha256', $signature), 1, $this->window * 2 + 60);
        } catch (Throwable $e) {
            report($e);

            return;
        }

        if (! $first) {
            throw InvalidServiceSignatureException::replayed();
        }
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
