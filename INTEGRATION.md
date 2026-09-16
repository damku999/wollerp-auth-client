# Integrating `wollerp/auth-client` into Coms Coupler

The phase-3 runbook. Ordered, and the order matters — every step before step 9 is
reversible, and step 9 is not.

This is written against the real Coms Coupler backend as it stands today:
Laravel **12.64.0**, PHP **^8.3**, `laravel/passport` **13.7.5**, two connections
(`auth_db`, `product_db`), and `App\Models\Auth\User` on `auth_db`. Line numbers
and counts below were measured, not estimated. Re-measure before you start; if
they have moved a lot, the plan has drifted and needs a second look.

> **Prerequisite.** `wollerp-auth` must be live, reachable, publishing JWKS, and
> already issuing `aud: ["cc"]` tokens that a CC user can obtain. Do not start
> step 1 until you can `curl` the JWKS endpoint from a CC app server.

---

## The shape of the change

CC has **88 files / 106 occurrences** referencing `App\Models\Auth\User`, and
**56** call sites using `Auth::id()` / `Auth::user()` / `$request->user()`. The
whole point of the approach below is that almost none of them get edited.

Only these actually change:

| What | Sites | Step |
|---|---|---|
| `auth:api` → `auth:wollerp` | **7 route groups** (`routes/api.php` ×5, `routes/auth.php` ×2) | 4 |
| `App\Models\Auth\User` class body | 1 file | 5 |
| SQL-level `'id'` column references | **9 expressions across 8 files** — or 0, if you take option A | 5 |
| New `/internal/revoke` route | 1 | 6 |
| Scheduler entry | 1 | 7 |

Everything else — every `created_by` join, every `$user->name`, every
`formatUserData()`, every eager load — keeps working because the class name,
the namespace and the attribute names do not move.

---

## 1 · `composer require`, with the VCS block and an exact pin

The package is not on Packagist. Add the repository to CC's `composer.json`
**above** `require`:

```json
"repositories": [
    {
        "type": "vcs",
        "url": "git@github.com:damku999/wollerp-auth-client.git"
    }
],
```

> ⚠️ **Confirm this URL before you use it.** The package's own working checkout
> currently has `origin` set to `git@github.com:damku999/wollerp-auth-client.git`,
> which is not the URL above. One of the two is a personal fork and the other is
> the canonical remote, and this document cannot tell which. Resolve it before
> step 1 — pointing a consumer at a fork means the exact version it pins is
> whatever that fork happens to tag, which defeats CONTRACT §8 entirely.
>
> ```bash
> git -C packages/wollerp-auth-client remote -v   # what the release is tagged on
> ```

Then:

```bash
composer require wollerp/auth-client:0.1.0
```

**`0.1.0`, exact — never `^0.1.0`, never `dev-main`.** CONTRACT §8: a floating
constraint on the component that validates every token is an unreviewed deploy.
`composer update` on an unrelated package would otherwise be able to change how
CC decides who is authenticated. Verify the pin landed as an exact constraint:

```bash
composer show wollerp/auth-client | head -3
grep -A2 '"wollerp/auth-client"' composer.json      # must read "0.1.0"
```

The package declares `illuminate/* ^12.0|^13.0`, so it composes with CC's
Laravel 12 without moving the framework. Confirm nothing else moved:

```bash
git diff composer.lock | grep -E '^\+ +"(name|version)"' | head -40
```

Package auto-discovery registers `WollerpAuthServiceProvider`. No manual
provider entry is needed.

---

## 2 · Publish the config and the two migrations

```bash
php artisan vendor:publish --tag=wollerp-auth-config
php artisan vendor:publish --tag=wollerp-auth-migrations
```

That writes `config/wollerp-auth.php` and two timestamped migrations creating
`users_mirror` (CONTRACT §4) and `revoked_tokens` (§6).

**Before migrating, apply the CC-specific edits to the published migrations.**
They are yours once published, and two things need adjusting:

**(a) `users_mirror` needs an `id` alias.** See step 5 for why. Add to the
published `create_users_mirror_table` migration, inside the `create` closure:

```php
// `auth_user_id` is the real primary key and MirrorSynchroniser writes to it by
// name — it cannot be renamed. But CC has 9 expressions that query the literal
// column `id` (BaseService::getUsersByIds, UserDataHelper, DropdownService,
// BaseCrudController, JoinRequestController, ActivityLogController,
// ResolvesWorkstreamCoordinators, ResolvesSubscriptionRecipients). A generated
// column makes all of them keep working untouched.
$table->unsignedInteger('id')->virtualAs('auth_user_id');
$table->index('id');
```

`virtualAs()` is supported by both the MariaDB and the SQLite grammars, so this
works in production and under the in-memory SQLite the test suite remaps to.

**(b) Both tables belong on `product_db`.** The stubs already read
`config('wollerp-auth.database.connection')` and call
`Schema::connection(...)`, so you do **not** edit the migrations for this — you
set `WOLLERP_AUTH_DB_CONNECTION=product_db` in step 3. Confirm before running:

```bash
php artisan migrate --pretend | grep -iE 'users_mirror|revoked_tokens'
```

Note this is the one place CC's "one migration file per table" rule does not
apply in the usual way: these files are *published output*, and re-publishing
after a package upgrade will offer to overwrite them. Keep the two edits above
in a reviewable commit so a future `--force` republish is easy to re-apply.

Then:

```bash
php artisan migrate
```

---

## 3 · Environment

```dotenv
# ── Identity: both are REQUIRED and have no default ──
WOLLERP_AUTH_ISSUER=https://auth.wollerp.lumicorelabs.com
WOLLERP_SERVICE_SLUG=cc

# ── Where the mirror and denylist live ──
WOLLERP_AUTH_DB_CONNECTION=product_db

# ── Service plane (CONTRACT §5) ──
WOLLERP_AUTH_URL=https://auth.wollerp.lumicorelabs.com
WOLLERP_HMAC_SECRET_AUTH=<the cc↔auth shared secret, from the secret manager>
WOLLERP_INTERNAL_IP_ALLOWLIST=10.0.0.0/8,<auth egress IP>

# ── Cold-start JWKS fallback. Not optional in production — see below ──
WOLLERP_AUTH_BUNDLED_JWKS=<base64 of the live JWKS document>

# ── Optional; defaults are correct for CC ──
# WOLLERP_AUTH_JWKS_URL       defaults to {issuer}/.well-known/jwks.json
# WOLLERP_AUTH_LEEWAY=60      hard-capped at 60s regardless
# WOLLERP_AUTH_JWKS_TTL=21600
```

### `WOLLERP_SERVICE_SLUG` has no default, deliberately

`config/wollerp-auth.php` reads `env('WOLLERP_SERVICE_SLUG')` with **no
fallback**, in two places (`audience` and `hmac.project`). `TokenValidator`
throws on construction when it is empty, and `Signer` throws when asked to sign
with it empty — the signer's guard is at the signing boundary rather than the
constructor, because a singleton that refuses to *exist* takes `php artisan
list` and `tinker` down with it on a product that has not been issued a secret
yet.

That is not an oversight and it must not be "fixed" by adding `'cc'` as the
default. CONTRACT §7 makes the product registry open — this same package ships
to Brick Case and Wollerp Enterprise. A baked-in `cc` default would mean a
Brick Case backend that forgot the variable would **silently announce itself as
Coms Coupler and accept Coms Coupler's tokens**. That is a cross-product
authentication bypass produced by a missing line in a `.env`.

Failing at boot is loud, immediate, and caught by the first request in staging.
Failing silently is caught by an incident. So: no default, and the failure is a
`InvalidArgumentException` naming the variable.

The same reasoning applies to `WOLLERP_AUTH_ISSUER` having no *meaningful*
default — the config ships the production issuer as a convenience, but an empty
value still refuses to construct rather than comparing `iss` against `''`.

**Verify before going further:**

```bash
php artisan tinker --execute="dd(app(Wollerp\AuthClient\Token\TokenValidator::class)->audience());"
# must print "cc" — if it throws, the variable is missing or config is cached stale
php artisan config:clear
php artisan wollerp:conformance          # names anything else still unwired
```

### `WOLLERP_AUTH_BUNDLED_JWKS` — the cold-start fallback

`jwks.bundled_keys` is the last thing between a JWKS outage and an auth outage.
It is consulted only when the endpoint is **unreachable** *and* nothing is
cached — which is precisely the state of a freshly booted host: a deploy, a
scale-out under load, a `cache:clear`, or a container restart during an Auth
incident. With it empty (the shipped default), §8 check 10 is a **503 across the
whole product** until Auth comes back. With it populated, that host serves
normally on key material it already trusts.

Populate it at deploy time:

```bash
# From a CC app server, which is also a useful test of egress to Auth.
curl -fsS https://auth.wollerp.lumicorelabs.com/.well-known/jwks.json | base64 -w0
# locally: curl -fsS http://auth.wollerp.test/.well-known/jwks.json | base64 -w0
```

Put the output in `WOLLERP_AUTH_BUNDLED_JWKS`. The variable accepts a full JWKS
document, a bare list of JWKs, or a single JWK — as raw JSON or base64. Prefer
base64: a JWKS document is full of `"`, `{` and `=`, which is miserable to quote
correctly in a `.env` and silently half-works when you get it wrong. Alternative:
paste the JWK literally into the published `config/wollerp-auth.php`, which puts
the rotation on the record in a reviewed diff. The two sources merge.

Then confirm it actually parsed and converts to a usable key — do not assume:

```bash
php artisan config:clear
php artisan wollerp:conformance --strict | grep bundled_keys
# posture.jwks.bundled_keys_present   PASS
# wiring.jwks.bundled_keys_usable     PASS
```

`wollerp:conformance` **warns** when the bundle is empty and **fails** when it is
present but unusable. A truncated or typo'd bundle is worse than an empty one:
the fallback looks configured, nobody looks at it again, and it does not fire on
the one morning it was needed.

**Refresh it on every signing-key rotation** (every 90 days — see §8 check 8).
A bundle holding only a rotated-out key is an empty bundle with extra steps.

This is not a trust escalation, before anyone asks. A bundled key still has to
match the token's `kid` and then verify the RS256 signature; `JwksClient` drops
anything that is not an RSA RS256 signing key of at least 2048 bits; and anyone
who can write this variable can already repoint `WOLLERP_AUTH_ISSUER`, which is
a far easier forgery than crafting a JWK.

---

## 4 · Swap `auth:api` for `auth:wollerp`

Add the guard to `config/auth.php`. The package registers the **driver**; the
guard entry is CC's:

```php
'guards' => [
    'web' => ['driver' => 'session', 'provider' => 'users'],

    // Kept during the soak period. Dual-accept IS the rollback (see step 9).
    'api' => ['driver' => 'passport', 'provider' => 'users'],

    // The package registers the `wollerp` driver. No provider: the guard
    // resolves the user from the mirror itself.
    'wollerp' => ['driver' => 'wollerp'],
],
```

Then change the **7 route groups**:

- `routes/api.php` lines ~137, ~144, ~153, ~162, ~552
- `routes/auth.php` lines ~69, ~105

```php
-Route::middleware(['auth:api', ResolveActiveProfile::class])->group(function () {
+Route::middleware(['auth:wollerp', ResolveActiveProfile::class])->group(function () {
```

Do **not** touch the rest of the stack. `ResolveActiveProfile`,
`CheckSubscription` and `EnforcePermission` all run after the guard and read the
authenticated user; they are LAYER 3 (CONTRACT §2) and stay exactly as they are.
That is the design: Auth answers *who*, CC's own tables answer *what may they
do*, on every request.

Two things to verify while you are here:

1. `config/auth.php` `defaults.guard` is `env('AUTH_GUARD', 'web')`. Leave it.
   Anything calling bare `Auth::user()` outside a route group resolves the
   *default* guard, not `wollerp`. Grep for `Auth::user()` / `Auth::id()` used
   outside a request that went through `auth:wollerp` — there are 56 such call
   sites and the overwhelming majority are inside controllers, which is fine.
2. CONTRACT §2 line 10 says profile context must be "resolved from `sub`, never
   from the request body". `ResolveActiveProfile` currently reads
   `active_profile_type` from `$request->input()`. Selecting *which of your own*
   profiles to act as, from the body, is legitimate — but confirm
   `ProfileContextResolver` validates that selection against the authenticated
   user's memberships before trusting it. If it does not, that is a
   privilege-escalation bug that predates this migration and must be fixed
   as part of phase 3, not after it.

Prefer the package's own 401 envelope on a route? Use the `wollerp.auth` alias
instead of `auth:wollerp`. CC's convention is `ApiResponser`, so `auth:wollerp`
plus CC's existing `JsonExceptionHandler` is the more consistent choice.

---

## 5 · The `users_mirror` repoint — the key move

**`App\Models\Auth\User` keeps its class name and its namespace. It stops being
an `Authenticatable` on `auth_db` and becomes a read-only projection over
`users_mirror` on `product_db`.**

### Why this, and not a rename

The obvious migration is "delete `App\Models\Auth\User`, use
`Wollerp\AuthClient\Mirror\MirroredUser` everywhere". That is a **106-occurrence
edit across 88 files**, touching 40+ models' `creator`/`updater` relations,
every service, every controller's eager-load array, and the seeders. A change
that size cannot be reviewed meaningfully, cannot be bisected when something
breaks, and has to land in one commit because the intermediate states do not
compile.

Keeping the class identity makes it a **one-file change**. Every
`use App\Models\Auth\User;` still resolves. Every
`->belongsTo(User::class, 'created_by')` still resolves. The two cross-database
chokepoints keep working:

- `BaseService::getUsersByIds()` (line ~47) —
  `User::whereIn('id', $userIds)->get()->keyBy('id')`
- `HasCrossDbUserTracking::getUserById()` (line ~156) — `User::find($userId)`,
  with its in-memory per-request cache
- `HasCrossDbUserTracking::formatUserData()` — returns `['id', 'name', 'email']`,
  all three of which exist on the mirror

`find()` goes through the primary key, so it works as-is. `whereIn('id', …)` is
the one that needs the generated column added in step 2 — see the caveat below.

### The model

```php
<?php

declare(strict_types=1);

namespace App\Models\Auth;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Read-only projection of the Wollerp auth server's user record — CONTRACT §4.
 *
 * This class deliberately keeps the name and namespace it had when it was an
 * Authenticatable on auth_db, so that 106 references across 88 files did not
 * have to be edited. What changed underneath it:
 *
 *   - connection      auth_db          → product_db
 *   - table           users            → users_mirror
 *   - primary key     id               → auth_user_id (aliased back to `id`
 *                                        by a generated column)
 *   - writes          allowed          → forbidden, always
 *   - password        hashed column    → DOES NOT EXIST AND NEVER WILL
 *
 * The product database must not be capable of authenticating anyone. There is
 * no password, no remember_token, no lockout state and no trusted_devices here;
 * those live on the auth server and are its business alone.
 *
 * `status` mirrors Auth's value verbatim and is free text. NEVER branch on it
 * for an authorization decision (CONTRACT §4) — that is LAYER 3's job, computed
 * from CC's own tables. It is here so user pickers can show "suspended".
 */
class User extends Model
{
    protected $connection = 'product_db';

    protected $table = 'users_mirror';

    protected $primaryKey = 'auth_user_id';

    public $incrementing = false;

    protected $keyType = 'int';

    public $timestamps = false;

    /** Nothing is mass assignable, because nothing is assignable. */
    protected $guarded = ['*'];

    protected function casts(): array
    {
        return [
            'auth_user_id' => 'integer',
            'version' => 'integer',
            'email_verified_at' => 'datetime',
            'synced_at' => 'datetime',
        ];
    }

    /**
     * CC serialises dates as dd/mm/yyyy HH:mm:ss. Preserved from the previous
     * model so every response that embeds a user keeps its existing format.
     */
    protected function serializeDate(\DateTimeInterface $date): string
    {
        return $date->format('d/m/Y H:i:s');
    }

    /**
     * The mirror is written ONLY by wollerp/auth-client's MirrorSynchroniser,
     * which writes through its own model. Any write attempted through this
     * class is a bug — most likely leftover code from before the separation —
     * and must fail loudly rather than corrupt a projection that the auth
     * server will silently overwrite on the user's next request anyway.
     */
    public function save(array $options = []): bool
    {
        throw new \LogicException(
            'users_mirror is a read-only projection of the auth server (CONTRACT §4). '
            .'Change the user at '.config('wollerp-auth.issuer').' instead.'
        );
    }

    public function delete(): ?bool
    {
        throw new \LogicException('users_mirror is a read-only projection (CONTRACT §4).');
    }

    /**
     * Replaces the old forApi() scope, which derived its column list from
     * $fillable — now empty, which would have selected the key alone.
     */
    public function scopeForApi(Builder $query): void
    {
        $query->select(['id', 'auth_user_id', 'auth_user_uuid', 'name', 'email', 'status']);
    }
}
```

### What you must delete from the old model, and why

| Removed | Why |
|---|---|
| `extends Illuminate\Foundation\Auth\User` | The mirror is not an authenticatable. `auth:wollerp` hands you `MirroredUser`; this class is for joins and pickers. |
| `HasApiTokens` (Passport) | Passport is being removed. Leaving it re-adds an `oauth_access_tokens` relation against a table that will not exist. |
| `SoftDeletes` | **Load-bearing.** `users_mirror` has no `deleted_at`. Leaving the trait appends `where deleted_at is null` to *every* query and breaks all 106 call sites with `Unknown column`. Deletions arrive as a `status` change in the feed (CONTRACT §5.4), not as a soft delete. |
| `HasActivityLogs` | Writes an activity log on save/delete. The model no longer saves. |
| `Notifiable` | Keep **only** if something still notifies a user via this model; it is harmless but pulls a `notifications` morph. Check before deciding. |
| `$fillable`, `$hidden`, `casts` for `password` etc. | Those columns do not exist. `$hidden` listing absent columns is harmless but misleading — drop it. |
| `revokeAllTokens()` | Writes to `oauth_refresh_tokens`. Revocation is now the auth server's job and arrives via the webhook in step 6. Delete it and fix its callers. |
| `scopeForCompany` / `forClient` / `forProfile` / `forRole` | **Keep.** They query `product_db.company_users` / `client_users` and then `whereIn('id', …)` — which now resolves against the generated column, on the same connection. They actually get *faster*: the `whereIn` is no longer a cross-database round trip. |

### The caveat you must not skip

The claim "the two chokepoints keep working untouched" is only true **with the
generated `id` column from step 2**. Without it, these 9 expressions fail with
`Unknown column 'id'`:

```
app/Services/BaseService.php:47                     User::whereIn('id', $userIds)
app/Helpers/AutoloadFiles/UserDataHelper.php:59     User::whereIn('id', $userIds)->get()->keyBy('id')
app/Helpers/AutoloadFiles/UserDataHelper.php:123    User::whereIn('id', $allUserIds)->get()->keyBy('id')
app/Services/DropdownService.php:1424               User::whereIn('id', $allUserIds)
app/Http/Controllers/BaseCrudController.php:640     User::whereIn('id', $allUserIds)
app/Http/Controllers/JoinRequestController.php:901  User::whereIn('id', $userIds)->get()->keyBy('id')
app/Http/Controllers/ActivityLogController.php:77   User::whereIn('id', $userIds)
app/Traits/ResolvesWorkstreamCoordinators.php:43    User::whereIn('id', …)
app/Traits/ResolvesSubscriptionRecipients.php:45    User::where('id', …)->value('email')
```

Two ways to resolve it. **Option A (recommended): the generated column.** Zero
application edits; all nine keep working; `keyBy('id')` and `$user->id` work
because `id` is a real selected column.

**Option B: edit the nine sites** to `whereIn((new User)->getKeyName(), …)` and
add a `getIdAttribute()` accessor for the `keyBy('id')` and `formatUserData()`
paths. Smaller schema, larger diff, and it leaves a trap for the next person who
writes `where('id', …)` out of habit.

Do **not** try to rename the primary key to `id`: `MirrorSynchroniser` writes
`updateOrCreate(['auth_user_id' => …], …)` with the column name hard-coded, so a
rename breaks all three sync layers.

---

## 6 · Own the `/internal/revoke` route

Auth → product. The package supplies the middleware and the writer; **the route
is CC's**, because the package must not add routes to an app that did not ask
for them.

Add to `routes/api.php` (outside every `auth:*` group — this is a service-plane
call with no user):

```php
use Wollerp\AuthClient\Revocation\DenylistChecker;

Route::post('/api/v1/internal/revoke', function (Request $request, DenylistChecker $denylist) {
    $denylist->revoke(
        $request->input('sid'),
        $request->input('jti'),
        $request->input('not_after'),   // ISO-8601 string, not a unix int
        $request->input('reason'),
    );

    return response()->noContent();
})->middleware('wollerp.hmac');
```

`wollerp.hmac` enforces **both** CONTRACT §5 controls: the IP allowlist from
`WOLLERP_INTERNAL_IP_ALLOWLIST` and the HMAC signature. Leave the allowlist
non-empty unless you have deliberately decided the load balancer owns it.

Three notes that will save you a debugging session:

- The inbound `X-Wollerp-Project` on this call is **`auth`**, not `cc`
  (CONTRACT §5.2 — the header names the *caller*). `WOLLERP_HMAC_SECRET_AUTH`
  populates the inbound map under exactly that key.
- Return **204**, and return it for a duplicate too. The sender treats any 4xx
  other than 429 as permanent and stops retrying; a 409 on a repeat delivery
  would be logged as a permanently failed revocation.
- Do not put this route behind `CheckSubscription` or `EnforcePermission`. There
  is no user and no active profile on this request.

---

## 7 · Backfill, then schedule the nightly reconcile

**Backfill first, before any user hits the new guard.** A cold mirror is not an
outage — layer 1 self-heals each user on their next request — but it means every
`created_by` join renders blank until each user happens to sign in.

```bash
php artisan users:sync --dry-run          # confirm reachability + signature
php artisan users:sync                    # full backfill
```

Reconcile the counts:

```sql
-- product_db
SELECT COUNT(*) FROM users_mirror;
-- auth server's users table, including soft-deleted; §5.4 says they are in the feed
```

A mismatch means the feed is being filtered somewhere. Deactivated and deleted
users **must** appear, with their current `status` — that is the whole point of
the backstop.

Then add the nightly entry to `routes/console.php`, alongside CC's existing
schedule:

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

03:30 is chosen to sit clear of CC's existing `routes/console.php` entries:
01:00 `subscription:check-expiry`, 02:00 `storage:recalculate --all`, and 03:00
`push:cleanup-logs`.

Verify it registered:

```bash
php artisan schedule:list | grep users:sync
```

---

## 8 · Verification checklist

Do not proceed to a production cutover until every line is green.

**The conformance suite, in CC's own CI — not just the package's.**

```bash
php artisan wollerp:conformance --strict
```

Running it in the package's own repo proves the package is correct. Running it
*inside CC* proves it is correct **with CC's PHP build, CC's OpenSSL, CC's
config cache, CC's `WOLLERP_SERVICE_SLUG`, CC's guard registration and CC's
`product_db` connection**. Those are the things that differ between a green
library and a broken deploy. Wire it into CC's pipeline permanently, not as a
one-off.

> **This instruction used to be wrong.** It said to run
> `vendor/bin/pest --testsuite=conformance` from inside CC. That could not work:
> Composer never loads a dependency's `autoload-dev`, so the package's `tests/`
> directory is not on CC's autoloader, and the harness needs
> `orchestra/testbench`, which CC has no reason to install. The assertions now
> ship in `src/`, so the artisan command above needs nothing installed, nothing
> published, and works against a warm `config:cache`. It makes no network calls,
> so it is safe on a production host and deterministic in a CI job with no
> egress.

It exits 0 or 1, prints `--json` for a pipeline to parse, and 42 checks have to
pass. A `suite.integrity` check asserts the run was not shortened, so "make the
gate green" cannot be done by deleting the thing that went red.

Equivalent, from CC's own Pest suite — which is the better place for it, because
it runs on every PR rather than only at deploy:

```php
use Wollerp\AuthClient\Conformance\ConformanceSuite;

it('validates Wollerp tokens correctly', function () {
    $report = app(ConformanceSuite::class)->run(strict: true);

    expect($report->passed())->toBeTrue($report->failureSummary());
});
```

| # | Check | Pass |
|---|---|---|
| 1 | `php artisan wollerp:conformance --strict` green inside CC's CI | exit 0, 42/42 |
| 2 | A valid `aud: ["cc"]` token opens a protected route | 200 |
| 3 | A token with `aud: ["bc"]` on the same route | 401, not 200 |
| 4 | An `alg: none` token, and an HS256 token signed with the JWKS public key | 401 both |
| 5 | **A revoked `sid` is refused on the next request** — log out on Auth, then replay the still-unexpired access token | 401 |
| 6 | `revoked_tokens` holds the row, with a populated `reason` | 1 row |
| 7 | Re-delivering the same webhook does not add a second row | still 1 row |
| 8 | **A rotated `kid` causes no 401s** — `auth:rotate-signing-key` on Auth, then hit CC immediately with a token signed by the new key | 200, no 401 spike |
| 9 | JWKS unreachable (block egress) with a warm cache | 200s continue |
| 10 | JWKS unreachable with a cold cache and no `bundled_keys` | **503**, not 401 |
| 10b | JWKS unreachable with a cold cache **and** `WOLLERP_AUTH_BUNDLED_JWKS` set | **200s continue** |
| 11 | `users_mirror` row count matches Auth's user count | equal |
| 12 | A `created_by` column renders a name on a list endpoint | populated |
| 13 | `Model::find()` on the mirror from tinker, then `->save()` | throws |
| 14 | `php artisan config:cache && php artisan route:cache`, then re-run check 1 and smoke the API | exit 0, 200 |

Check 8 is the one people skip and the one that bites. Rotation is a *routine*
operation — every 90 days — and if an unknown `kid` produces 401s instead of a
throttled refetch, every user in the estate is signed out four times a year.
Watch CC's logs during the rotation, not just the response codes.

Checks 9 and 10 distinguish `jwks_unavailable` from `jwks_unusable`. Both must
be 503. A 401 there sends users back through login for a fault on our side.

Check 10b is the one 10 exists to motivate. 10 documents what an empty bundle
costs; 10b proves you have stopped paying it. Run them in that order on the same
host so the difference is attributable to the bundle and nothing else, and
re-run 10b after every signing-key rotation — see §3.

Check 14 is not just a smoke test. `config:cache` is where a correct `.env`
stops being the thing the application reads, and it is the single most common
way a verified staging configuration turns into a broken production one.
Re-running check 1 *after* caching is what catches it, because the conformance
command reads the same cached config the request path does.

---

## 9 · What gets deleted afterwards — and why it is phase 5, not now

**Nothing in this list is removed during phase 3.**

- `laravel/passport` from `composer.json`
- `HasApiTokens` from any remaining model
- `AppServiceProvider::configurePassportTokens()` (~line 170), its call site in
  `boot()` (~line 114), and the `use Laravel\Passport\Passport;` import (line 37)
- The `'api' => ['driver' => 'passport']` guard in `config/auth.php`
- `oauth_access_tokens`, `oauth_refresh_tokens`, `oauth_clients`,
  `oauth_auth_codes`, `oauth_personal_access_clients` in `auth_db`
- `App\Models\Auth\Token`, `Client`, `RefreshToken`, `AuthCode`
- The login / register / password-reset / OTP / 2FA controllers, their Form
  Requests and their routes in `routes/auth.php`
- **`auth_db.users.password`** — and `remember_token`, `failed_login_attempts`,
  `account_locked_until`, `lockout_level`, `total_lockouts`, `trusted_devices`
- The `OAuthServerException` handling in `bootstrap/app.php`

### Why the wait

**Dual-accept is the rollback.** For the whole soak period CC keeps the `api`
(Passport) guard registered and its tables intact, so backing out is a one-line
revert of the 7 route groups — no migration, no data restore, no coordinated
downtime. The moment you drop the `oauth_*` tables, the rollback becomes "restore
`auth_db` from backup", which is an outage with a recovery-time objective
measured in hours instead of seconds.

The failure modes this protects against are the slow ones, and they are exactly
the ones a smoke test does not find:

- A cron job, a webhook handler, a mobile client on an old build, or a partner
  integration still presenting a Passport token. These surface over *days*, not
  minutes.
- A JWKS rotation misbehaving — which cannot be observed until a rotation
  actually happens, 90 days out.
- A `users:sync` drift that only shows up on a user who has not signed in for
  weeks.

**Suggested gate for phase 5.** All of these, not any of them:

1. ≥ 30 days on `auth:wollerp` in production.
2. **Zero** successful Passport authentications in the last 14 days. Instrument
   this — log a warning with the route and client on every token the `api` guard
   accepts, and grep for it. Do not infer it from traffic shape.
3. At least one real signing-key rotation completed with no 401 spike.
4. `users_mirror` reconciled clean on 14 consecutive nightly runs.
5. A tested `auth_db` restore, taken *after* the cutover.

**Drop `password` last, and separately.** It is the single irreversible step —
the hashes cannot be regenerated, and once it is gone CC cannot authenticate
anyone under any circumstance, including a total Auth outage. Give it its own
change window, its own backup, and its own sign-off, after everything else in
this section has been gone for at least a week.
