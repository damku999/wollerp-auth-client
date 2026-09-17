<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Jwks;

use Illuminate\Http\Client\Factory as HttpFactory;
use Throwable;
use Wollerp\AuthClient\Exceptions\JwksException;
use Wollerp\AuthClient\Support\Base64Url;
use Wollerp\AuthClient\Support\CaBundle;

/**
 * CONTRACT §3. Resolves a token's `kid` to a PEM public key.
 *
 * Resolution order, and it matters:
 *
 *   cached set → forced refetch (throttled) → bundled fallback → 401
 *
 * and inside a fetch:
 *
 *   live endpoint → last known good → bundled fallback → 503
 *
 * The JWK → PEM conversion is done here, once, at cache-write time. Only RSA
 * keys declaring RS256 (or declaring nothing) are accepted; an EC or oct entry
 * appearing in the document is dropped rather than stored, because an `oct`
 * entry reaching a verifier is how HMAC confusion attacks start.
 */
final class JwksClient
{
    /** OID 1.2.840.113549.1.1.1 — rsaEncryption. */
    private const RSA_OID = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

    /**
     * @param  array<int, array<string, mixed>>  $bundledKeys  Raw JWKs shipped with the deploy.
     * @param  string  $caBundle  Optional CA to verify the JWKS host against. Naming one
     *                            is the only TLS lever there is — see Support\CaBundle.
     */
    public function __construct(
        private readonly HttpFactory $http,
        private readonly JwksCache $cache,
        private readonly string $url,
        private readonly array $bundledKeys = [],
        private readonly int $timeout = 5,
        private readonly string $caBundle = '',
    ) {}

    /**
     * @return string PEM-encoded RSA public key
     *
     * @throws JwksException
     */
    public function publicKeyFor(string $kid): string
    {
        $keys = $this->cache->keys();
        $alreadyFresh = false;

        if ($keys === null) {
            $keys = $this->fetch();
            $alreadyFresh = true;
        }

        if (isset($keys[$kid])) {
            return $keys[$kid];
        }

        // Unknown kid. The auth server publishes current + previous, so this is
        // either a rotation we have not seen or a forged token. One throttled
        // refetch tells us which — but not if we only just fetched, or a cold
        // cache would mean two identical round trips per unknown kid.
        if (! $alreadyFresh && $this->cache->claimRefetchSlot()) {
            $keys = $this->fetch();

            if (isset($keys[$kid])) {
                return $keys[$kid];
            }
        }

        $bundled = $this->convertSet($this->bundledKeys);

        if (isset($bundled[$kid])) {
            return $bundled[$kid];
        }

        throw JwksException::unknownKey($kid);
    }

    /**
     * Force a refresh. Used by deploy hooks and tests, never on the hot path.
     *
     * @return array<string, string>
     */
    public function refresh(): array
    {
        $this->cache->flush();

        return $this->fetch();
    }

    /**
     * @return array<string, string>
     *
     * @throws JwksException
     */
    private function fetch(): array
    {
        $failure = null;
        $unusable = false;

        try {
            $response = $this->http
                ->timeout($this->timeout)
                ->acceptJson()
                ->withOptions(CaBundle::options($this->caBundle))
                ->get($this->url);

            if ($response->successful()) {
                $document = $response->json();

                if (is_array($document)) {
                    $keys = $this->convertSet($document['keys'] ?? []);

                    if ($keys !== []) {
                        $this->cache->put($keys);

                        return $keys;
                    }

                    // Reached it, parsed it, and there is nothing in it we are
                    // willing to verify with — every entry was EC, oct, wrong
                    // `use`, undersized or malformed. A different incident from
                    // an outage, with a different fix, so it gets its own
                    // reason rather than being reported as "unreachable".
                    $unusable = true;
                }
            }
        } catch (Throwable $exception) {
            $failure = $exception;
        }

        // The endpoint is down, slow, or publishing something unusable. Do not
        // turn that into an estate-wide 401 storm.
        $lastKnownGood = $this->cache->lastKnownGood();

        if ($lastKnownGood !== null) {
            return $lastKnownGood;
        }

        $bundled = $this->convertSet($this->bundledKeys);

        if ($bundled !== []) {
            return $bundled;
        }

        throw $unusable
            ? JwksException::unusable($this->url)
            : JwksException::unreachable($this->url, $failure);
    }

    /**
     * @param  mixed  $keys
     * @return array<string, string>
     */
    private function convertSet(mixed $keys): array
    {
        if (! is_array($keys)) {
            return [];
        }

        $converted = [];

        foreach ($keys as $jwk) {
            if (! is_array($jwk)) {
                continue;
            }

            $kid = $jwk['kid'] ?? null;

            if (! is_string($kid) || $kid === '') {
                continue;
            }

            $pem = $this->toPem($jwk);

            if ($pem !== null) {
                $converted[$kid] = $pem;
            }
        }

        return $converted;
    }

    /**
     * @param  array<string, mixed>  $jwk
     */
    private function toPem(array $jwk): ?string
    {
        if (($jwk['kty'] ?? null) !== 'RSA') {
            return null;
        }

        $alg = $jwk['alg'] ?? 'RS256';

        if ($alg !== 'RS256') {
            return null;
        }

        $use = $jwk['use'] ?? 'sig';

        if ($use !== 'sig') {
            return null;
        }

        $n = is_string($jwk['n'] ?? null) ? Base64Url::decode($jwk['n']) : null;
        $e = is_string($jwk['e'] ?? null) ? Base64Url::decode($jwk['e']) : null;

        if ($n === null || $e === null || $n === '' || $e === '') {
            return null;
        }

        // Reject undersized moduli outright. 2048 bits = 256 bytes; anything
        // smaller is not a key we should ever be asked to trust.
        if (strlen(ltrim($n, "\x00")) < 256) {
            return null;
        }

        $rsaPublicKey = self::sequence(
            self::unsignedInteger($n).self::unsignedInteger($e)
        );

        $algorithmIdentifier = self::sequence(
            self::tagged(0x06, self::RSA_OID).self::tagged(0x05, '')
        );

        $subjectPublicKeyInfo = self::sequence(
            $algorithmIdentifier.self::tagged(0x03, "\x00".$rsaPublicKey)
        );

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
            ."-----END PUBLIC KEY-----\n";

        // Prove it parses before we cache it; a malformed entry must not become
        // a cached landmine that fails every request for the next six hours.
        return openssl_pkey_get_public($pem) === false ? null : $pem;
    }

    private static function sequence(string $contents): string
    {
        return self::tagged(0x30, $contents);
    }

    private static function tagged(int $tag, string $contents): string
    {
        return chr($tag).self::length(strlen($contents)).$contents;
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)).$bytes;
    }

    private static function unsignedInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '') {
            $bytes = "\x00";
        }

        // DER INTEGER is signed; a leading bit of 1 needs a zero pad.
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00".$bytes;
        }

        return self::tagged(0x02, $bytes);
    }
}
