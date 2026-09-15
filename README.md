# wollerp/auth-client

Validates RS256 access tokens issued by `wollerp-auth`. Every product backend installs
this package. **It never issues a token and holds no signing key** — it only ever holds
public keys fetched from JWKS.

Implements LAYER 1 and LAYER 2 of [`CONTRACT.md`](../../CONTRACT.md) §2. LAYER 3
(profile context, subscription, permission) is product-owned and deliberately absent.

Requires PHP 8.3+ and Laravel 12 or 13. Auth runs 13; Coms Coupler stays on 12 until
after phase 5, so nothing here may depend on a version-specific framework internal.

---

## Install

```bash
composer require wollerp/auth-client:0.1.0      # exact version, never a caret — CONTRACT §8
php artisan vendor:publish --tag=wollerp-auth-config
php artisan vendor:publish --tag=wollerp-auth-migrations
php artisan migrate
```

Add the guard. The package registers the **driver**; the guard entry is yours:

```php
// config/auth.php
'guards' => [
    'wollerp' => ['driver' => 'wollerp'],
],
```

Protect routes with `auth:wollerp`, or with the `wollerp.auth` middleware alias if you
want the package's own 401 envelope instead of Laravel's.

```php
Route::middleware('wollerp.auth')->group(function () { … });
Route::middleware('wollerp.hmac')->prefix('api/v1/internal')->group(function () { … });
```

### Environment

| Variable | Required | Notes |
|---|---|---|
| `WOLLERP_AUTH_ISSUER` | **yes** | Exact string compared to `iss`. No default. |
| `WOLLERP_SERVICE_SLUG` | **yes** | This product's registry slug (CONTRACT §7). No default. |
| `WOLLERP_AUTH_JWKS_URL` | no | Defaults to `{issuer}/.well-known/jwks.json` |
| `WOLLERP_AUTH_LEEWAY` | no | Default 60 s. **Hard-capped at 60 s.** |
| `WOLLERP_AUTH_DB_CONNECTION` | no | Where the mirror and denylist live. CC: `product_db`. |
| `WOLLERP_HMAC_SECRET_AUTH` | for `/internal/*` | Distinct secret per service pair. |
| `WOLLERP_INTERNAL_IP_ALLOWLIST` | recommended | Comma-separated CIDRs or addresses. |

**There is no default slug and no default issuer, and both must be non-empty or
`TokenValidator` refuses to construct.** CONTRACT §7 makes the product registry open,
so this package ships to every product; a baked-in default would mean a mis-deployed
backend silently announces itself as somebody else and accepts that product's tokens.
Fail loudly at boot beats fail silently forever.

---

## The integration contract, on one page

### What you get

```php
// Verified claims for this request — never null inside `wollerp.auth`.
$claims = Wollerp\AuthClient\Http\Middleware\Authenticate::claims($request);

$claims->sub();     // ULID — global identity across all products
$claims->uid();     // int  — legacy id, preserves your created_by joins
$claims->sid();     // ULID — session / refresh-token family
$claims->jti();     // ULID — this token
$claims->ver();     // int  — mirror version
$claims->email(); $claims->name(); $claims->emailVerified();
$claims->amr();     // ['pwd', 'otp', …]

// Offline re-auth gate for sensitive operations. No call to the auth server.
$claims->authenticatedWithin(300);   // false when auth_time is absent — fails closed
$claims->authenticatedWith('totp');

// The mirror row, as an Authenticatable with no credential surface.
$request->user();                    // Wollerp\AuthClient\Mirror\MirroredUser
```

### What you do NOT get, and must answer yourself

`roles`, `permissions`, `subscription`, `plan`, `modules`, `active_profile_type`,
`company_id`, `client_id`, `professional_id`.

A token carrying authority is a stale cache with a 15-minute lifetime: revoke a
permission and the holder keeps it until their token expires. Auth answers *who is
this*; your database answers *what may they do*, on every request, from `sub`.

### Outbound service calls

```php
$headers = app(Wollerp\AuthClient\Hmac\Signer::class)->headers($rawJsonBody);
// X-Wollerp-Project, X-Wollerp-Timestamp, X-Wollerp-Signature
```

Sign the **raw** bytes you are about to send. Re-encoding JSON changes key order,
unicode escaping and float formatting, and the receiver would MAC different bytes.

### Revocation webhook

`POST /api/v1/internal/revoke` is **yours to route**; the package supplies the
middleware and the writer:

```php
Route::post('/api/v1/internal/revoke', function (Request $request, DenylistChecker $denylist) {
    $denylist->revoke(
        $request->input('sid'),
        $request->input('jti'),
        $request->input('not_after'),   // ISO-8601 string — see below
        $request->input('reason'),
    );

    return response()->noContent();
})->middleware('wollerp.hmac');
```

Three things about that payload, because the sender is not hypothetical —
`App\Jobs\DispatchRevocationWebhook` posts `{ sid, jti, not_after, reason }`:

- **`not_after` is an ISO-8601 string, not a unix integer.** `revoke()` accepts
  `int`, `string` or `DateTimeInterface` and normalises, so the handler above can
  forward the raw input. An unparsable value stores `null`, which means the row is
  never pruned — retaining a revocation too long is the safe direction to fail.
- **`reason` is stored and never checked.** It is not in the denylist predicate
  (CONTRACT §6); it exists so incident response can answer "was this session killed
  by logout, by reuse detection, or by an admin?".
- **Repeat deliveries are idempotent.** The webhook has six attempts and a backoff
  schedule; re-revoking the same `(sid, jti)` updates the existing row instead of
  inserting a duplicate.

### Mirror

`users_mirror` is a read-only projection. **No password column, ever** — the product
database must not be capable of authenticating anyone. Every write through
`MirroredUser` throws unless it originates in `MirrorSynchroniser`; that includes
`saveQuietly()` and `deleteQuietly()`, which an event-based guard would miss. The one
thing it cannot stop is a raw `DB::table('users_mirror')->update(...)`. Nothing in PHP
can; that is the residual risk.

Three sync layers, each covering the previous one's failure: token-driven upsert on
every request → webhook → `php artisan users:sync --since=` nightly.

---

## The JWT library decision — `firebase/php-jwt` was dropped

**This package has no JWT dependency.** Verification is `openssl_verify()` with a
hard-coded `OPENSSL_ALGO_SHA256`, about thirty lines in
[`TokenValidator`](src/Token/TokenValidator.php), plus a JWK→PEM converter in
[`JwksClient`](src/Jwks/JwksClient.php).

The reasoning, since dropping a well-regarded library is not the default answer:

**1. The pin becomes structural rather than configured.** This package's single most
important job is that the algorithm is a property of the verifier and the token does not
get a vote. `alg: none` and HS256-signed-with-the-RSA-public-key are both *complete*
authentication bypasses — the public key is published at JWKS for anyone to fetch, so an
attacker who can choose the algorithm holds the "secret" and can mint a token for any
user. With a library, the pin is an argument you pass (`JWT::decode($t, $keys)`, allowed
algorithms derived from the key set) and it stays correct only as long as every future
caller keeps passing it correctly. Here there is no argument, no config key and no code
path that varies by algorithm. The header's `alg` is read once, to reject anything that
is not the literal string `RS256`, and is never used to select a routine or a key type.

**2. `firebase/php-jwt` 7.1.1 is a major bump from the 6.x most of this estate knows.**
Adopting a new major of the component that decides whether a request is authenticated,
at the same moment as separating auth into its own service, stacks two risks that do not
need to be taken together.

**3. Zero supply-chain surface on the hot path.** Every authenticated request in every
product runs this code. The dependency footprint is `ext-openssl` and `ext-json`.

**4. The scope genuinely is small.** One algorithm, one key type, one token shape.
We do not need JWE, nested JWTs, ES/PS families, or `crit` handling. Most of a JWT
library is capability we would be carrying in order not to use it — and each of those
capabilities is a branch an attacker can try to steer the verifier into.

**The honest cost.** Hand-rolled crypto plumbing is a standing liability, and the
mitigation is the conformance suite below, not confidence. Two specific things we now
own that a library would have owned: strict base64url decoding
([`Base64Url`](src/Support/Base64Url.php) rejects padding, whitespace and the
standard-base64 alphabet) and DER/SPKI construction for the JWK→PEM conversion, which is
validated with `openssl_pkey_get_public()` before anything is cached so a malformed entry
cannot become a cached landmine. If the suite ever becomes inconvenient enough that
someone wants to weaken it, that is the signal to revisit this decision — not a reason
to delete a test.

---

## Conformance suite

Mandatory. Generates a real 2048-bit RSA keypair at runtime — no fixtures, no
checked-in keys, no dependency on the auth server being reachable — and mints both
genuine tokens and the exact tokens an attacker would try.

```bash
composer test:conformance
```

| File | Guards |
|---|---|
| `AcceptsValidToken` | The happy path, and that no authority claim leaks into the token |
| `RejectsAlgNone` | The oldest bypass: a verifier that honours the header skips signature checking entirely |
| `RejectsHs256SignedWithPublicKey` | Algorithm confusion. **The single most important test here.** |
| `RejectsWrongIssuer` | Exact match. Lookalikes a `str_starts_with` check would let through |
| `RejectsWrongAudience` | A Brick Case token must not open a Coms Coupler session |
| `RejectsExpired` | The 15-minute TTL is the backstop for the whole revocation design |
| `RejectsDenylistedSid` | LAYER 2 — logout and reuse detection actually biting |
| `RejectsTamperedSignature` | Signature verification actually happening |
| `RejectsUnknownKid` | Rotation, throttled refetch, and JWKS outage ≠ auth outage |
| `Leeway` | The 60-second cap enforced in code, not just documented |

> **Windows dev boxes.** `openssl_pkey_new()` fails with
> `error:80000003:system library::No such process` when `OPENSSL_CONF` is not set for
> the CLI `php.ini`. Point it at your PHP build's `extras/ssl/openssl.cnf` before
> running the suite. `TokenFactory` says so in the exception message too.

---

## Design notes worth knowing before you change something

- **No Laravel facades in `src/`.** Everything is constructor-injected, so the whole
  package is testable without booting a framework and nothing depends on global state.
- **Leeway is clamped, not validated.** A bad config value degrades to the safe maximum
  rather than throwing. Leeway is the knob an operator reaches for when a clock problem
  is causing 401s, and widening it to an hour "temporarily" extends the life of every
  revoked and expired token in the estate by an hour.
- **`expires_at` is not in the denylist predicate.** Pruning removes rows once the last
  token they could match has expired. Adding `AND expires_at > NOW()` would let clock
  skew between the pruning host and the request host resurrect a revoked session.
- **A JWKS outage is a 503, not a 401.** Two distinct reasons: `jwks_unavailable` (we
  could not reach it and hold nothing cached or bundled) and `jwks_unusable` (we reached
  it and it published no key we will trust). Different incidents, different fixes. Both
  are kept out of the 401 noise so they land on an availability board — and a 401 would
  send users back through login for a fault on our side.
- **Forced JWKS refetches are throttled**, so unknown-kid traffic cannot be used to make
  us hammer the auth server. Cold-cache fetches do not spend the throttle slot: the
  fetch that filled the cache *is* the fresh copy.
- **`bundled_keys`** is the last-resort fallback when the endpoint is unreachable *and*
  nothing is cached. Populate it at deploy time so a JWKS outage on a cold cache is not
  an auth outage.
- **`users:sync` carries `#[AsCommand]` deliberately.** Laravel only defers instantiating
  commands that have it; without it the command — and therefore the `Signer`, which
  refuses to exist without an HMAC secret — is constructed at console boot, and a product
  that has not been issued a secret yet could not run `php artisan` at all.
