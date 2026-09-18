# wollerp/auth-client

Validates RS256 access tokens issued by `wollerp-auth`. Every product backend installs
this package. **It never issues a token and holds no signing key** — it only ever holds
public keys fetched from JWKS.

Implements LAYER 1 and LAYER 2 of [`CONTRACT.md`](../../docs/CONTRACT.md) §2. LAYER 3
(profile context, subscription, permission) is product-owned and deliberately absent.

Requires PHP 8.3+ and Laravel 12 or 13. Auth runs 13; Coms Coupler stays on 12 until
after phase 5, so nothing here may depend on a version-specific framework internal.

| Doc | Read it when |
|---|---|
| [`INTEGRATION.md`](INTEGRATION.md) | Standing up a **new** product backend. Eight steps. |
| [`INTEGRATION-coms-coupler.md`](INTEGRATION-coms-coupler.md) | Migrating a product that **already has its own authentication** and must keep serving traffic while it moves. Passport, dual-accept, soak period, legacy call sites. |

---

## Install

```bash
composer require wollerp/auth-client:0.1.0      # exact version, never a caret — CONTRACT §8
php artisan vendor:publish --tag=wollerp-auth-config
php artisan vendor:publish --tag=wollerp-auth-migrations
php artisan migrate
```

The published migrations need no edits. They resolve their connection from the
published config, they ship Pint-clean, and `users_mirror` already carries the generated
`id` column (`virtualAs('auth_user_id')`, on MySQL/MariaDB/SQLite) that keeps
`where('id', …)` and `keyBy('id')` working — so `vendor:publish --force` after an
upgrade is safe.

Add the guard. The package registers the **driver**; the guard entry is yours:

```php
// config/auth.php
'guards' => [
    'wollerp' => ['driver' => 'wollerp'],
],
```

Protect routes with the `wollerp.auth` alias:

```php
Route::middleware('wollerp.auth')->group(function () { … });
Route::middleware('wollerp.hmac')->prefix('api/v1/internal')->group(function () { … });
```

**Prefer `wollerp.auth` over `auth:wollerp`, even though the latter reads better.**
Laravel's own `Authenticate` reaches the guard through `Guard::check()`, and
`TokenGuard::user()` correctly swallows exceptions and returns null because the `Guard`
contract requires it — so every failure arrives at Laravel as "not authenticated" and
gets a **401**, including a JWKS outage, which CONTRACT §3 says is a **503**. A 401
there sends users back through login for a fault on our side. `wollerp.auth` makes that
distinction itself.

Use `auth:wollerp` only if you map the exception family in your own handler:

```php
$exceptions->render(fn (WollerpAuthException $e) => response()->json(
    ['success' => false, 'error' => $e->reason()], $e->status(),
));
```

### Environment

| Variable | Required | Notes |
|---|---|---|
| `WOLLERP_AUTH_ISSUER` | **yes** | Exact string compared to `iss`. No default. Asserted at boot. |
| `WOLLERP_SERVICE_SLUG` | **yes** | This product's registry slug (CONTRACT §7). No default. Asserted at boot. |
| `WOLLERP_AUTH_JWKS_URL` | no | Defaults to `{issuer}/.well-known/jwks.json` |
| `WOLLERP_AUTH_LEEWAY` | no | Default 60 s. **Hard-capped at 60 s.** |
| `WOLLERP_AUTH_DB_CONNECTION` | no | **Leave unset on a single-database product** — unset means the default connection, tables and migration ledger included. Set it only when the product genuinely runs several connections and the business data is not on the default one (Coms Coupler: `product_db`). |
| `WOLLERP_HMAC_SECRET_AUTH` | for `/internal/*` | Distinct secret per service pair. |
| `WOLLERP_INTERNAL_IP_ALLOWLIST` | recommended | Comma-separated CIDRs or addresses. |
| `WOLLERP_AUTH_BUNDLED_JWKS` | production | Cold-start JWKS fallback. Without it, a JWKS outage on a cold cache is a 503 across the product. |

**There is no default slug and no default issuer.** CONTRACT §7 makes the product
registry open, so this package ships to every product; a baked-in default would mean a
mis-deployed backend silently announces itself as somebody else and accepts that
product's tokens. Both are asserted **at boot**, not at the first token — `TokenValidator`
is a lazy singleton, so without the boot check a deploy missing the variable starts
cleanly, answers `/up` with a 200, passes a smoke test, and then fails for every real
user. In the console the assertion applies to `config:cache`, `optimize` and the
long-running request servers only, so `vendor:publish` and `migrate` still work on a
product that has not been configured yet.

### Registering the client with Auth changes redirect-URI validation

Config on the auth server, but it belongs here because it is found the hard way. Once
`client_id` maps to a product slug in the registry, **`redirect_uri` validation reads
the registry's URI list rather than the URI column on the OAuth client row.** Registering
the id without also registering the URI fails the authorize step with a 400 *before any
authorization code is issued*, and the error does not name the list it consulted — so it
looks like a redirect-URI typo and is not one. Register both together, and prove it with
a real authorize request rather than by reading the client row.

### Laravel puts back the auth surface you deleted

Laravel 11+ recursively merges its own shipped `config/auth.php` into yours, so a product
with no `User` model and an almost-empty `config/auth.php` still resolves a session
guard, an eloquent provider pointing at the deleted class, and a password-reset broker —
none of which appear in the file a reviewer reads. A config file cannot delete a key the
merge adds, so the package removes the entries that **cannot work** during `register()`:
an eloquent provider whose model class does not exist, plus the guards, brokers and
default-broker reference that then dangle. A product that still has a User model is
untouched.

```bash
php artisan tinker --execute="dd(config('wollerp-auth.runtime.pruned_auth_config'));"
```

`WOLLERP_AUTH_HARDEN_AUTH_CONFIG=false` turns it off; see
`src/Support/AuthConfigHardener.php` for the exact rules and what is deliberately left
alone.

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
    $written = $denylist->revoke(
        $request->input('sid'),
        $request->input('jti'),
        $request->input('not_after'),   // ISO-8601 string — see below
        $request->input('reason'),
    );

    if (! $written) {
        return response()->json([
            'success' => false,
            'message' => 'Either sid or jti is required.',
        ], 422);
    }

    return response()->noContent();
})->middleware('wollerp.hmac');
```

Four things about that payload, because the sender is not hypothetical —
`App\Jobs\DispatchRevocationWebhook` posts `{ sid, jti, not_after, reason }`:

- **Every parameter is `mixed` and normalised**, so forwarding `$request->input(...)`
  straight in is safe under `declare(strict_types=1)`. `{"sid": 12345}` is matched on
  as `"12345"`; a non-scalar becomes null. A narrower signature would make a malformed
  body a **500 on a service-plane call**, which the sender treats as retryable and
  re-delivers five more times, each failing identically.
- **`revoke()` returns `false` when the payload named neither `sid` nor `jti`**, which
  is what the 422 above is for. Answering 204 would tell the auth server a revocation it
  never performed had succeeded, and it would stop retrying.
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

Mandatory, and it runs in two places for two different reasons.

It generates a real 2048-bit RSA keypair at runtime — no fixtures, no checked-in
keys, no dependency on the auth server being reachable — and mints both genuine
tokens and the exact tokens an attacker would try.

### In a consumer — the one that gates a deploy

```bash
php artisan wollerp:conformance --strict
```

Ships in `src/`, so there is nothing to install, nothing to publish and no test
framework involved. It runs against **this product's** real `issuer`, `audience`,
`leeway` and length limit — the live values, including a warm `config:cache` —
and then checks the live guard, middleware aliases, denylist connection and
mirror. It makes no network calls and never touches the real JWKS cache, so it
is safe on a production host and deterministic in CI with no egress.

Exit code 0 or 1. Wire it into the pipeline, not into a runbook.

| Flag | |
|---|---|
| `--strict` | Treat posture warnings as failures. Use this in CI. |
| `--json` | The full report as JSON, for a pipeline to parse. |
| `--quiet-passes` | Only failures, warnings and skips. |

Or, from the product's own Pest / PHPUnit suite:

```php
use Wollerp\AuthClient\Conformance\ConformanceSuite;

it('validates Wollerp tokens correctly', function () {
    $report = app(ConformanceSuite::class)->run(strict: true);

    expect($report->passed())->toBeTrue($report->failureSummary());
});
```

> Earlier revisions of INTEGRATION.md said to run `pest --testsuite=conformance`
> from inside the consuming app. That never worked — Composer does not load a
> dependency's `autoload-dev`, so these test files are not on a product's
> autoloader, and the harness needs `orchestra/testbench`. The assertions moved
> into `src/` for exactly that reason.

### In this repo — the one that proves the package is correct

```bash
composer test:conformance
```

| Area | Guards |
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
| `ShippedSuite` | That the consumer-facing suite is green when the wiring is right, **red when it is wrong**, and cannot be quietly shrunk |

### Why a check cannot be quietly dropped

`ConformanceSuite::CHECKS` is the manifest. A `suite.integrity` check compares
what actually executed against it, and against `BYPASS_GUARDS` — the subset that
guards a complete authentication bypass. Deleting a check fails the run instead
of shortening it, in the package *and* in every consumer, and `ShippedSuiteTest`
pins the same thing from the other side.

This is deliberate. Everything in that subset is also something somebody could
be tempted to delete at 2am when it goes red during a release.

> **Windows dev boxes.** `openssl_pkey_new()` fails with
> `error:80000003:system library::No such process` when `OPENSSL_CONF` is not set for
> the CLI `php.ini`. Point it at your PHP build's `extras/ssl/openssl.cnf` before
> running the suite. `TokenForge` says so in the exception message too.

---

## `composer.lock` is committed, which is not what a library normally does

Composer ignores a dependency's lock file entirely, so this one has no effect on
any consumer. The orthodox advice is therefore to gitignore it, and for almost
every library that advice is right.

It is committed here for one reason: **this package's dev dependency tree
executes arbitrary code that decides whether the estate's authentication gate
passes.** Pest, its plugins, PHPUnit and Testbench all run in-process during the
run that certifies `alg` is pinned to RS256. Without a lock:

- a green run is not reproducible — "165 passed" on a laptop and "165 passed" in
  CI were not necessarily runs against the same code, and last month's green run
  cannot be re-created at all, which makes bisecting a regression guesswork;
- a yanked, compromised or silently-republished dev package enters the run with
  nothing recording what changed. The lock pins exact versions *and* dist
  references, so that shows up as a diff.

### The cost, stated plainly

Committing the lock narrows what CI proves from "any resolution the constraints
allow" to "this one". For a library declaring `illuminate/* ^12.0|^13.0` that is
a real loss: the lock can sit on Laravel 13 for a year while every consumer runs
12, and CI would never notice the package had stopped working on 12.

That loss is recoverable and the reproducibility loss is not, which is what
decides it. `.github/workflows/ci.yml` runs three kinds of job:

| Job | Lock | Proves |
|---|---|---|
| `locked` | `composer install --locked` | A specific commit + a specific tree is green, reproducibly, on PHP 8.3 and 8.4 |
| `floating` | `composer update`, `--prefer-lowest` and highest | The declared constraint range actually works, not just the locked point in it |
| `shipped-suite` | locked, then `dump-autoload --no-dev` | The conformance suite is reachable with no dev autoload — i.e. from inside a consumer |

**If you ever drop the `floating` jobs, ignore the lock again.** Keeping the lock
without them is strictly worse than not having it: you would be trading real
coverage for reproducibility you were no longer checking.

Consumers are unaffected either way — they pin `wollerp/auth-client:0.1.0`
exactly, per CONTRACT §8, and resolve their own tree.

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
  nothing is cached. Populate it at deploy time from `WOLLERP_AUTH_BUNDLED_JWKS` (a JWKS
  document, a bare list of JWKs or a single JWK, as raw JSON or base64) so a JWKS outage
  on a cold cache is not an auth outage. An unparsable value degrades to an empty list
  rather than throwing — it is read inside a config file, and a config file that throws
  takes every `php artisan` command with it. `wollerp:conformance` warns on an empty
  bundle and **fails** on one that is present but unusable, because a fallback that looks
  configured and is not is worse than no fallback at all.
- **`users:sync` carries `#[AsCommand]` deliberately.** Laravel only defers instantiating
  commands that have it; without it every command is constructed at console boot, which
  is how the original `Signer` constructor guard managed to break `php artisan list` on
  any product not yet issued an HMAC secret. That guard now lives in `sign()`, so signing
  without a secret is still impossible and merely existing unconfigured is fine — but the
  attribute stays, because construction-at-boot is a trap the next dependency will fall
  into too.
