<?php

declare(strict_types=1);

use Wollerp\AuthClient\Mirror\MirroredUser;
use Wollerp\AuthClient\Support\BundledKeys;

return [

    /*
    |--------------------------------------------------------------------------
    | Issuer
    |--------------------------------------------------------------------------
    |
    | CONTRACT §1. Compared to the token's `iss` claim with an exact string
    | match. Never prefix or suffix matched.
    |
    */

    'issuer' => env('WOLLERP_AUTH_ISSUER', 'https://auth.wollerp.lumicorelabs.com'),

    /*
    |--------------------------------------------------------------------------
    | Audience — this service's slug
    |--------------------------------------------------------------------------
    |
    | CONTRACT §7. The slug of the product this backend IS. A token is accepted
    | only when its `aud` array contains this value.
    |
    | The product registry is OPEN, not a closed enum — it grows whenever the
    | company launches something, and adding a product must cost one config
    | entry, one OAuth client row and one HMAC secret. So there is deliberately
    | no list of valid slugs here and no default: this package ships to every
    | product, and a baked-in default would mean a mis-deployed backend silently
    | announces itself as somebody else and accepts that product's tokens.
    |
    | Unset means unconfigured, and TokenValidator refuses to construct.
    |
    */

    'audience' => env('WOLLERP_SERVICE_SLUG'),

    /*
    |--------------------------------------------------------------------------
    | Auth server base URL
    |--------------------------------------------------------------------------
    |
    | Used by the service plane client (users:sync). Not used for token
    | validation, which is fully offline.
    |
    */

    'base_url' => env('WOLLERP_AUTH_URL', 'https://auth.wollerp.lumicorelabs.com'),

    /*
    |--------------------------------------------------------------------------
    | Token validation
    |--------------------------------------------------------------------------
    |
    | There is deliberately NO `algorithm` key here. The algorithm is pinned to
    | RS256 in the verifier (CONTRACT §2) and must never be configurable or
    | read from the token header — both are total authentication bypasses.
    |
    | `leeway` is hard-capped at 60 seconds by TokenValidator regardless of what
    | is configured here.
    |
    */

    'token' => [
        'leeway' => (int) env('WOLLERP_AUTH_LEEWAY', 60),
        'max_length' => (int) env('WOLLERP_AUTH_MAX_TOKEN_LENGTH', 8192),
    ],

    /*
    |--------------------------------------------------------------------------
    | JWKS
    |--------------------------------------------------------------------------
    |
    | CONTRACT §3. Cached on the file driver for 6 hours, refetched when a token
    | arrives with an unknown `kid`. `refetch_cooldown` throttles those forced
    | refetches so unknown-kid traffic cannot be used to hammer the auth server.
    |
    | `bundled_keys` is the last-resort fallback used only when the endpoint is
    | unreachable AND nothing is cached. Populate it with the current public JWK
    | at deploy time so a JWKS outage on a cold cache is not an auth outage.
    |
    | Two ways to populate it, and they merge — use whichever suits the deploy:
    |
    |   1. WOLLERP_AUTH_BUNDLED_JWKS, which takes a JWKS document, a bare list
    |      of JWKs or a single JWK, as raw JSON or base64. Base64 is the sane
    |      choice in a .env file:
    |
    |        WOLLERP_AUTH_BUNDLED_JWKS="$(curl -fsS \
    |          https://auth.wollerp.lumicorelabs.com/.well-known/jwks.json | base64 -w0)"
    |
    |   2. Literal entries in the array below, in a published config file that
    |      goes through review. Preferred when the key rotation is planned and
    |      you want the diff on the record.
    |
    | An unparsable env value yields an empty list — the same behaviour as not
    | setting it — so a bad value degrades to today's 503 and never throws out
    | of a config file. `php artisan wollerp:conformance` fails outright on a
    | bundle that is present but unusable, because that is worse than an empty
    | one: the fallback looks configured and will not fire.
    |
    | This is not a trust escalation. A bundled key still has to match the
    | token's `kid` and verify the RS256 signature, JwksClient drops anything
    | that is not an RSA RS256 signing key of at least 2048 bits, and anyone
    | who can set this variable can already repoint WOLLERP_AUTH_ISSUER.
    |
    */

    'jwks' => [
        'url' => env(
            'WOLLERP_AUTH_JWKS_URL',
            rtrim((string) env('WOLLERP_AUTH_ISSUER', 'https://auth.wollerp.lumicorelabs.com'), '/').'/.well-known/jwks.json'
        ),
        'cache_store' => env('WOLLERP_AUTH_JWKS_CACHE_STORE', 'file'),
        'cache_key' => env('WOLLERP_AUTH_JWKS_CACHE_KEY', 'wollerp-auth:jwks'),
        'ttl' => (int) env('WOLLERP_AUTH_JWKS_TTL', 21600),
        'refetch_cooldown' => (int) env('WOLLERP_AUTH_JWKS_REFETCH_COOLDOWN', 60),
        'http_timeout' => (int) env('WOLLERP_AUTH_JWKS_TIMEOUT', 5),
        'bundled_keys' => array_merge(
            BundledKeys::fromEnv(env('WOLLERP_AUTH_BUNDLED_JWKS')),
            [
                // [
                //     'kty' => 'RSA',
                //     'use' => 'sig',
                //     'alg' => 'RS256',
                //     'kid' => '2026-09',
                //     'n'   => '…base64url…',
                //     'e'   => 'AQAB',
                // ],
            ],
        ),
    ],

    /*
    |--------------------------------------------------------------------------
    | Guard
    |--------------------------------------------------------------------------
    |
    | The package registers a `wollerp` guard DRIVER. Add the guard itself to
    | config/auth.php:
    |
    |   'wollerp' => ['driver' => 'wollerp'],
    |
    */

    'guard' => env('WOLLERP_AUTH_GUARD', 'wollerp'),

    /*
    |--------------------------------------------------------------------------
    | Database
    |--------------------------------------------------------------------------
    |
    | The mirror and the denylist live in the PRODUCT database. For Coms Coupler
    | that is `product_db`, not the default connection.
    |
    */

    'database' => [
        'connection' => env('WOLLERP_AUTH_DB_CONNECTION'),
        'mirror_table' => env('WOLLERP_AUTH_MIRROR_TABLE', 'users_mirror'),
        'revoked_table' => env('WOLLERP_AUTH_REVOKED_TABLE', 'revoked_tokens'),
    ],

    /*
    |--------------------------------------------------------------------------
    | User mirror
    |--------------------------------------------------------------------------
    |
    | CONTRACT §4. Token-driven upsert is layer 1 of 3. Turning this off means
    | the mirror can only be filled by the webhook and `users:sync`.
    |
    */

    'mirror' => [
        'enabled' => (bool) env('WOLLERP_AUTH_MIRROR_ENABLED', true),
        'model' => MirroredUser::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Service plane HMAC
    |--------------------------------------------------------------------------
    |
    | CONTRACT §5. A distinct secret per service pair. `secrets` is the INBOUND
    | map keyed by the value of the X-Wollerp-Project header. `outbound` is the
    | secret this service signs its own calls to the auth server with.
    |
    | `allowed_ips` is the second of the two required controls. Leave it empty
    | only if the IP allowlist is enforced upstream (load balancer / firewall).
    |
    | `project` is the same open-registry slug as `audience` above and carries
    | the same no-default rule, for the same reason.
    |
    */

    'hmac' => [
        'project' => env('WOLLERP_SERVICE_SLUG'),
        'window' => 300,
        'secrets' => array_filter([
            'auth' => env('WOLLERP_HMAC_SECRET_AUTH'),
        ]),
        'outbound' => env('WOLLERP_HMAC_SECRET_AUTH'),
        'allowed_ips' => array_values(array_filter(
            explode(',', (string) env('WOLLERP_INTERNAL_IP_ALLOWLIST', ''))
        )),
    ],

    /*
    |--------------------------------------------------------------------------
    | Bulk sync
    |--------------------------------------------------------------------------
    |
    | CONTRACT §5: product → auth, GET /api/v1/internal/users?since=
    |
    */

    'sync' => [
        'endpoint' => env('WOLLERP_AUTH_SYNC_ENDPOINT', '/api/v1/internal/users'),
        'per_page' => (int) env('WOLLERP_AUTH_SYNC_PER_PAGE', 500),
        'timeout' => (int) env('WOLLERP_AUTH_SYNC_TIMEOUT', 30),
    ],

];
