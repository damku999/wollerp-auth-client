<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Handles;

use Illuminate\Http\Client\Factory as HttpFactory;
use Throwable;
use Wollerp\AuthClient\Exceptions\HandleRegistryException;
use Wollerp\AuthClient\Hmac\Signer;
use Wollerp\AuthClient\Support\CaBundle;

/**
 * Product → Auth, CONTRACT §5.6: POST /api/v1/internal/handles/{check,reserve,confirm,release}.
 *
 * The product is never a body field — it is the X-Wollerp-Project this Signer
 * stamps, which Auth verifies. Bodies come back in the standard envelope; a
 * refusal's reason is `Data.error_code` (HDL_*), mapped in
 * HandleRegistryException::CODES. Anything else that is not a 2xx with a
 * readable `Data` is `unavailable`: a product must fail closed on it.
 */
final class HandleRegistryClient
{
    public const KIND_USER = 'user';

    public const KIND_COMPANY = 'company';

    public const KIND_CLIENT = 'client';

    private const CONNECT_TIMEOUT_SECONDS = 3;

    public function __construct(
        private readonly HttpFactory $http,
        private readonly Signer $signer,
        private readonly string $baseUrl,
        private readonly string $endpoint,
        private readonly int $timeout,
        private readonly string $caBundle = '',
    ) {}

    /**
     * Passing the owner makes "my own handle" count as available.
     *
     * @throws HandleRegistryException
     */
    public function check(string $handle, ?string $kind = null, ?int $accountId = null, ?int $authUserId = null): bool
    {
        $data = $this->call('check', [
            'handle' => $handle,
            'kind' => $kind,
            'account_id' => $accountId,
            'auth_user_id' => $authUserId,
        ]);

        return ($data['available'] ?? null) === true;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws HandleRegistryException
     */
    public function reserve(string $handle, string $kind, ?int $accountId = null, ?int $authUserId = null): array
    {
        return $this->call('reserve', [
            'handle' => $handle,
            'kind' => $kind,
            'account_id' => $accountId,
            'auth_user_id' => $authUserId,
        ]);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws HandleRegistryException
     */
    public function confirm(string $handle, ?int $accountId = null): array
    {
        return $this->call('confirm', ['handle' => $handle, 'account_id' => $accountId]);
    }

    /**
     * Idempotent: false (nothing to free) is not an error.
     *
     * @throws HandleRegistryException
     */
    public function release(string $handle, ?int $accountId = null): bool
    {
        $data = $this->call('release', ['handle' => $handle, 'account_id' => $accountId]);

        return ($data['released'] ?? null) === true;
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed> the envelope's `Data`
     *
     * @throws HandleRegistryException
     */
    private function call(string $operation, array $payload): array
    {
        $url = rtrim($this->baseUrl, '/').'/'.trim($this->endpoint, '/').'/'.$operation;

        try {
            // Encode once, sign those bytes, send those bytes (CONTRACT §5).
            $rawBody = json_encode(
                array_filter($payload, static fn (mixed $value): bool => $value !== null),
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
            );

            $response = $this->http
                ->timeout($this->timeout)
                ->connectTimeout(self::CONNECT_TIMEOUT_SECONDS)
                ->acceptJson()
                ->withOptions(CaBundle::options($this->caBundle))
                ->withHeaders($this->signer->headers($rawBody))
                ->withBody($rawBody, 'application/json')
                ->post($url);
        } catch (Throwable $exception) {
            // Unreachable, timed out, TLS refused — or no secret to sign with,
            // which is a deployment fault with the same answer: we did not ask.
            throw HandleRegistryException::unavailable($operation.': '.$exception->getMessage(), $exception);
        }

        $body = $response->json();
        $data = is_array($body) ? ($body['Data'] ?? null) : null;

        if ($response->successful() && is_array($data)) {
            return $data;
        }

        $reason = is_array($data) ? (HandleRegistryException::CODES[$data['error_code'] ?? ''] ?? null) : null;

        if ($reason !== null && $response->clientError()) {
            throw HandleRegistryException::refused($reason, $response->status());
        }

        throw HandleRegistryException::unavailable(sprintf('%s answered HTTP %d', $operation, $response->status()));
    }
}
