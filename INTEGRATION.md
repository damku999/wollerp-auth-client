# Integrating `wollerp/auth-client`

Standing a **new** product backend up as a Wollerp resource server. Eight steps,
none of them long. If everything goes well this is an afternoon.

> **Migrating a product that already has its own authentication?** This is not
> your document. See [`INTEGRATION-coms-coupler.md`](INTEGRATION-coms-coupler.md),
> which covers the soak period, dual-accept as a rollback, and what to do about
> call sites that predate the auth server. About half of it is inapplicable to a
> greenfield product, which is exactly why the two are separate files.

**Prerequisite.** `wollerp-auth` must be live, reachable and publishing JWKS, and
your product's slug must be registered there — see step 0. Do not start step 1
until you can `curl` the JWKS endpoint from an app server.

---

## 0 · Register the product with Auth first

This step is config on the **auth server**, not code here, and it has to happen
first because nothing downstream can be tested without it. It needs:

| | |
|---|---|
| A slug | Two letters, from CONTRACT §7. `cc`, `bc`, `we`, `mf` are taken or reserved. This is what goes in `aud`. |
| An OAuth client row | `client_id` + the product's redirect URIs. |
| An HMAC secret | Distinct per service pair (CONTRACT §5). Never reuse another product's. |
| A registry entry | The product's URL, enabled flag, IP allowlist. |

### Registering the client id changes how redirect URIs are validated

Worth knowing before you spend an afternoon on it: **once `client_id` maps to a
product slug in the registry, `redirect_uri` validation reads the registry's URI
list, not the URI column on the OAuth client row.** Registering the id without
also registering the URI therefore fails the authorize step with a 400 *before
any authorization code is issued* — and the error does not say the URI list it
actually consulted.

The failure looks like a redirect-URI typo and is not one, which is what makes it
expensive. Register both, together, and then prove it with a real authorize
request rather than by reading the client row:

```bash
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  "https://auth.wollerp.lumicorelabs.com/oauth/authorize?client_id=<id>&redirect_uri=<uri>&response_type=code&code_challenge=<c>&code_challenge_method=S256"
# 302 back to your redirect_uri = registered correctly
# 400                           = the registry does not have this URI
```

---

## 1 · Install, with an exact pin

The package is not on Packagist. Add the repository to `composer.json` **above**
`require`:

```json
"repositories": [
    {
        "type": "vcs",
        "url": "git@github.com:damku999/wollerp-auth-client.git"
    }
],
```

```bash
composer require wollerp/auth-client:0.1.0
```

**Exact — never `^0.1.0`, never `dev-main`.** CONTRACT §8: a floating constraint
on the component that validates every token is an unreviewed deploy, and
`composer update` on an unrelated package would be able to change how this
product decides who is authenticated.

Auto-discovery registers `WollerpAuthServiceProvider`. No manual provider entry.

---

## 2 · Publish and migrate

```bash
php artisan vendor:publish --tag=wollerp-auth-config
php artisan vendor:publish --tag=wollerp-auth-migrations
php artisan migrate
```

That writes `config/wollerp-auth.php` and two migrations creating `users_mirror`
(CONTRACT §4) and `revoked_tokens` (§6). **They need no edits** — they read their
connection and table names from the published config, they ship Pint-clean, and
`users_mirror` already carries the generated `id` column described below, so
`vendor:publish --force` after a package upgrade is safe.

### About that `id` column

`auth_user_id` is the real primary key, because `MirrorSynchroniser` writes it by
name. But `id` is Laravel's default route key, the default `keyBy()` argument and
what everybody types from habit, so the migration also creates `id` as a
generated column reading `auth_user_id`. `$user->id`, `where('id', …)`,
`whereIn('id', …)` and `keyBy('id')` all work, and none of it can be written to.

It is created on MySQL, MariaDB and SQLite. On any other driver it is **skipped**
— a driver with no generated-column support silently ignores `virtualAs()` and
would otherwise produce a NOT NULL column with no value. If that is you, either
add the equivalent for your driver or use `getKeyName()` everywhere.

### Which connection?

**Leave `WOLLERP_AUTH_DB_CONNECTION` unset unless the product genuinely runs more
than one database connection.** Unset means "the default connection", which is
the right answer for a single-database product — you do not need to invent a
second connection to install this package. Both tables and both `migrations`
ledger rows follow this one key.

Set it only when the business data lives somewhere other than the default
connection. Coms Coupler does (`product_db`, from before the separation) and it
is not the norm.

```bash
php artisan migrate --pretend | grep -iE 'users_mirror|revoked_tokens'
```

---

## 3 · Environment

```dotenv
# ── Identity: both REQUIRED, no defaults, checked at boot ──
WOLLERP_AUTH_ISSUER=https://auth.wollerp.lumicorelabs.com
WOLLERP_SERVICE_SLUG=<your slug>

# ── Service plane (CONTRACT §5) ──
WOLLERP_AUTH_URL=https://auth.wollerp.lumicorelabs.com
WOLLERP_HMAC_SECRET_AUTH=<the <slug>↔auth shared secret, from the secret manager>
WOLLERP_INTERNAL_IP_ALLOWLIST=10.0.0.0/8,<auth egress IP>

# ── Cold-start JWKS fallback. Not optional in production — see below ──
WOLLERP_AUTH_BUNDLED_JWKS=<base64 of the live JWKS document>

# ── Only if this product runs multiple connections ──
# WOLLERP_AUTH_DB_CONNECTION=

# ── Optional; the defaults are correct ──
# WOLLERP_AUTH_JWKS_URL       defaults to {issuer}/.well-known/jwks.json
# WOLLERP_AUTH_LEEWAY=60      hard-capped at 60s regardless
# WOLLERP_AUTH_JWKS_TTL=21600
```

### The slug has no default, and the container will not boot without one

`config/wollerp-auth.php` reads `env('WOLLERP_SERVICE_SLUG')` with **no
fallback**, in two places (`audience` and `hmac.project`). That is not an
oversight and it must not be "fixed" by adding your own slug as the default:
CONTRACT §7 makes the product registry open and this same package ships to every
product, so a baked-in default would mean a backend that forgot the variable
**silently announces itself as another product and accepts that product's
tokens**. That is a cross-product authentication bypass produced by a missing
line in a `.env`.

The package asserts both variables **at boot**, so a deploy missing one fails its
health check instead of starting cleanly, answering `/up` with a 200, passing a
smoke test and then failing for every real user. In the console the assertion
applies to `config:cache`, `optimize` and the long-running request servers only,
so `vendor:publish` and `migrate` still work before the `.env` is complete.

```bash
php artisan config:clear
php artisan tinker --execute="dd(app(Wollerp\AuthClient\Token\TokenValidator::class)->audience());"
php artisan wollerp:conformance          # names anything else still unwired
```

### `WOLLERP_AUTH_BUNDLED_JWKS` — the cold-start fallback

`jwks.bundled_keys` is the last thing between a JWKS outage and an auth outage.
It is consulted only when the endpoint is **unreachable** *and* nothing is cached
— which is precisely the state of a freshly booted host: a deploy, a scale-out
under load, a `cache:clear`, or a container restart during an Auth incident. Left
empty (the shipped default), §7 check 8 is a **503 across the whole product**
until Auth comes back.

```bash
# From an app server, which is also a useful test of egress to Auth.
curl -fsS https://auth.wollerp.lumicorelabs.com/.well-known/jwks.json | base64 -w0
```

The variable accepts a full JWKS document, a bare list of JWKs, or a single JWK,
as raw JSON or base64. Prefer base64: a JWKS document is full of `"`, `{` and
`=`, which is miserable to quote in a `.env` and silently half-works when you get
it wrong. You can also paste the JWK into the published config, which puts the
rotation on the record in a reviewed diff. The two sources merge.

Then confirm it parsed and converts to a usable key — do not assume:

```bash
php artisan config:clear
php artisan wollerp:conformance --strict | grep bundled_keys
# posture.jwks.bundled_keys_present   PASS
# wiring.jwks.bundled_keys_usable     PASS
```

**Refresh it on every signing-key rotation** (every 90 days — see §7 check 6). A
bundle holding only a rotated-out key is an empty bundle with extra steps.

---

## 4 · Declare the guard

The package registers the **driver**; the guard entry is yours.

```php
// config/auth.php
'defaults' => [
    'guard' => env('AUTH_GUARD', 'wollerp'),
],

'guards' => [
    // No `provider` key on purpose: this guard resolves the caller from
    // users_mirror itself and hands back a MirroredUser, which has no password,
    // no remember token and no credential surface of any kind.
    'wollerp' => ['driver' => 'wollerp'],
],

'providers' => [],
```

Point `defaults.guard` at `wollerp`. A bare `Auth::user()` outside a route group
then resolves the same thing the middleware does, rather than falling through to
a session guard that can never be populated — which gives you a `check()` that is
always false and no error to explain it.

There is no `passwords` block and no `password_timeout`. Password reset is the
auth server's job and only its job.

> **You do not have to delete the rest by hand.** Laravel 11+ recursively merges
> its own shipped `config/auth.php` into yours, so emptying this file does not
> empty the configuration — `guards.web`, `providers.users` (pointing at a
> `User` model you deleted) and `passwords.users` all come back, invisibly,
> because they are not in the file you are reading. The package removes the ones
> that cannot work at `register()` time. `config('wollerp-auth.runtime.pruned_auth_config')`
> lists exactly what it removed; `WOLLERP_AUTH_HARDEN_AUTH_CONFIG=false` turns it
> off.

---

## 5 · Protect routes

**Use the `wollerp.auth` alias.**

```php
Route::middleware('wollerp.auth')->group(function () { … });
```

`auth:wollerp` also works and reads more naturally, and it is the wrong default.
Here is why, because it is not obvious and it is the kind of thing that is only
discovered during an incident:

Laravel's own `Authenticate` middleware reaches the guard through
`Guard::check()`. `TokenGuard::user()` correctly swallows `WollerpAuthException`
and returns null — the `Guard` contract requires it to — so **every** failure
arrives at Laravel as "not authenticated", and Laravel answers **401**. That
includes a JWKS outage, which CONTRACT §3 says must be a **503**. A 401 there
sends users back through login for a fault on our side, and the incident hides
inside the 401 noise instead of showing on an availability board.

`wollerp.auth` makes that distinction itself: 401 with an RFC 6750
`WWW-Authenticate` challenge for a bad token, 503 with a `Retry-After` for
`jwks_unavailable` and `jwks_unusable`.

### If you want `auth:wollerp` anyway

Entirely reasonable — a product with an established response envelope will prefer
its own handler over the package's. The price is that you **must** map the
exception family yourself, or §7 checks 7 and 8 cannot pass:

```php
// bootstrap/app.php
->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(function (WollerpAuthException $e, Request $request) {
        return response()->json([
            'success' => false,
            'error' => $e->reason(),
        ], $e->status());   // 401 for a bad token, 503 for a JWKS problem
    });
});
```

`WollerpAuthException` is the base class for everything this package throws on a
request. `status()` and `reason()` are its whole public surface, and both are
safe to return to the caller.

(`UnconfiguredIdentityException` from step 3 is deliberately **not** in that
family. It is a deployment defect, not a request outcome, and mapping it onto a
401 would send every user through login because of a missing `.env` line.)

---

## 6 · Own the `/internal/revoke` route

Auth → product. The package supplies the middleware and the writer; **the route
is yours**, because the package must not add routes to an app that did not ask
for them.

```php
use Wollerp\AuthClient\Revocation\DenylistChecker;

Route::post('/api/v1/internal/revoke', function (Request $request, DenylistChecker $denylist) {
    $written = $denylist->revoke(
        $request->input('sid'),
        $request->input('jti'),
        $request->input('not_after'),   // ISO-8601 string, not a unix int
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

Outside every `auth:*` group — this is a service-plane call with no user — and
not behind subscription or permission middleware, for the same reason.

Four things that will save you a debugging session:

- **`revoke()` takes `mixed` and normalises.** Forwarding `$request->input(...)`
  straight in is safe under `declare(strict_types=1)`: `{"sid": 12345}` is
  matched on as `"12345"`, and a non-scalar becomes null and reports `false`. A
  narrower signature would make a malformed body a **500 on a service-plane
  call**, which the sender treats as retryable and re-delivers five more times.
- **`not_after` is an ISO-8601 string, not a unix integer.** `revoke()` accepts
  `int`, `string` or `DateTimeInterface`. An unparsable value stores `null`,
  which means the row is never pruned — retaining a revocation too long is the
  safe direction to fail.
- **Return 204, including for a duplicate.** Delivery is retried six times with
  backoff and re-revoking the same `(sid, jti)` updates the existing row rather
  than inserting a second. A 409 on a repeat would be logged as a permanently
  failed revocation.
- **The inbound `X-Wollerp-Project` is `auth`**, not your slug — the header names
  the *caller* (CONTRACT §5.2). `WOLLERP_HMAC_SECRET_AUTH` populates the inbound
  map under exactly that key.

---

## 7 · Backfill and schedule the reconcile

**Backfill before any user hits the new guard.** A cold mirror is not an outage —
layer 1 self-heals each user on their next request — but every `created_by` join
renders blank until each user happens to sign in.

```bash
php artisan users:sync --dry-run          # confirm reachability + signature
php artisan users:sync                    # full backfill
```

Reconcile the count against Auth's `users` table **including soft-deleted rows**:
CONTRACT §5.4 puts them in the feed, with their current `status`, and that is the
whole point of the backstop. A mismatch means the feed is being filtered
somewhere.

Then schedule the nightly reconcile:

```php
Schedule::command('users:sync --since=' . now()->subDay()->toIso8601String())
    ->dailyAt('03:30')
    ->onOneServer()
    ->withoutOverlapping();
```

**The 24-hour `--since` window overlaps the previous run on purpose.** The
endpoint paginates by keyset on an immutable ULID, so a row updated *behind* an
in-flight cursor is missed by that scan. The overlap is what collects it. Do not
"optimise" this to start exactly where the last run stopped.

---

## 8 · Verification checklist

Nine lines. Do not go to production until every one is green.

**Wire the conformance suite into CI first, not into a runbook.**

```bash
php artisan wollerp:conformance --strict
```

Running it in the package's own repo proves the package is correct. Running it
*inside this product* proves it is correct **with this product's PHP build, its
OpenSSL, its config cache, its `WOLLERP_SERVICE_SLUG`, its guard registration and
its database connection** — which are the things that differ between a green
library and a broken deploy. It makes no network calls, so it is safe on a
production host and deterministic in CI with no egress. Exit code 0 or 1,
`--json` for a pipeline to parse.

Equivalent, and better, from the product's own Pest suite, because it then runs
on every pull request rather than only at deploy:

```php
use Wollerp\AuthClient\Conformance\ConformanceSuite;

it('validates Wollerp tokens correctly', function () {
    $report = app(ConformanceSuite::class)->run(strict: true);

    expect($report->passed())->toBeTrue($report->failureSummary());
});
```

A `suite.integrity` check asserts the run was not shortened, so "make the gate
green" cannot be done by deleting the thing that went red.

| # | Check | Pass |
|---|---|---|
| 1 | `wollerp:conformance --strict` green in this product's CI | exit 0 |
| 2 | A valid token with your slug in `aud` opens a protected route | 200 |
| 3 | A token for a **different** product's slug on the same route | 401, not 200 |
| 4 | An `alg: none` token, and an HS256 token signed with the JWKS public key | 401 both |
| 5 | **A revoked `sid` is refused on the next request** — log out on Auth, then replay the still-unexpired access token | 401 |
| 5b | `revoked_tokens` holds one row with a populated `reason`, and re-delivering the same webhook does not add a second | 1 row |
| 6 | **A rotated `kid` causes no 401s** — rotate on Auth, then hit this product immediately with a token signed by the new key | 200, no 401 spike |
| 7 | JWKS unreachable (block egress) with a warm cache | 200s continue |
| 8 | JWKS unreachable with a cold cache and no `bundled_keys` | **503**, not 401 |
| 8b | Same, **with** `WOLLERP_AUTH_BUNDLED_JWKS` set | **200s continue** |
| 9 | `php artisan config:cache && php artisan route:cache`, then re-run check 1 and smoke the API | exit 0, 200 |

**Check 6 is the one people skip and the one that bites.** Rotation is a routine
operation — every 90 days — and if an unknown `kid` produces 401s instead of a
throttled refetch, every user in the estate is signed out four times a year.
Watch the logs during the rotation, not just the response codes.

**Checks 7 and 8 must be 503, not 401.** If you took `auth:wollerp` in step 5,
they cannot pass without the render hook. A 401 here is the missing handler, not
a token problem.

**Check 8b is the one 8 exists to motivate.** 8 documents what an empty bundle
costs; 8b proves you have stopped paying it. Run them in that order on the same
host so the difference is attributable to the bundle and nothing else, and re-run
8b after every rotation.

**Check 9 is not a smoke test.** `config:cache` is where a correct `.env` stops
being the thing the application reads, and it is the single most common way a
verified staging configuration turns into a broken production one. Re-running
check 1 *after* caching is what catches it, because the conformance command reads
the same cached config the request path does.

---

## What you get, and what you still owe

The package answers **who is this**, and nothing else:

```php
$claims = Wollerp\AuthClient\Http\Middleware\Authenticate::claims($request);

$claims->sub();     // ULID — global identity across all products
$claims->uid();     // int  — legacy id, preserves created_by joins
$claims->sid();     // ULID — session / refresh-token family
$claims->jti();     // ULID — this token
$claims->authenticatedWithin(300);   // offline re-auth gate, no call to Auth

$request->user();   // MirroredUser — no password, no remember token
```

It does **not** give you `roles`, `permissions`, `subscription`, `plan`,
`modules`, `active_profile_type` or any tenancy id, and it never will. A token
carrying authority is a stale cache with a 15-minute lifetime: revoke a
permission and the holder keeps it until their token expires. Your database
answers *what may they do*, on every request, resolved from `sub` — never from
the request body.

That is LAYER 3 of CONTRACT §2, and it is yours.
