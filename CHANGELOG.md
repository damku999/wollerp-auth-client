# Changelog

All notable changes to `wollerp/auth-client` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the public surface may change in a minor release.
CONTRACT §8 requires consumers to pin an **exact** version — `0.1.0`, never
`^0.1.0` and never `dev-main`. This package decides who is authenticated on every
request across the whole estate; a floating constraint means an unrelated
`composer update` can change that decision without review.

## [Unreleased]

### Fixed

- **A failed refetch is no longer reported as an unknown key.** `JwksClient`
  served last-known-good or bundled material when the endpoint was down and,
  if the token's `kid` was in none of it, threw `unknownKey` — a 401 — although
  the auth server had never been asked about that kid. Measured live on Coms
  Couplers (19 Sep 2026): key rotated, JWKS down, cache cold, bundle stale →
  every fresh token answered `token_signing_key_unknown` and its holder was sent
  back through login for an outage on our side. The client now remembers why
  the last fetch fell back and, when the kid is absent after such a fetch,
  throws that fetch's `jwks_unavailable` / `jwks_unusable` (503) instead. The
  throttled path is unchanged on purpose: a warm cache, no refetch slot and an
  absent kid is still a 401 — nothing failed, the kid is not in a fresh document.
- **`Http\Middleware\Authenticate`'s docblock said it "converts any failure
  into a 401".** It never did — `deny()` maps the exception's own status, 503
  with `Retry-After` included. The docblock now says what the code does, and
  why that is the reason to prefer the alias over `auth:wollerp`.

### Changed

- `INTEGRATION-coms-coupler.md` records what Coms Couplers actually shipped for
  route protection after §8 check 10 answered 401 with the render hook in
  place: a product-owned middleware calling `authenticateRequest()` directly.
  The "render hook makes `auth:wollerp` safe" claim is withdrawn — the hook is
  never reached.
- The conformance harness's validator now reads a **faked live** JWKS document
  carrying the forge's key instead of the offline 503, because an unpublished
  kid can only be judged "unknown" against a document the client believes it
  received. Still no network: the factory is faked and stray requests throw.
  `pin.signature.unknown_kid` keeps its meaning; the bundled-key path is still
  exercised by `wiring.jwks.bundled_keys_usable`.

Portability work. Brick Case was the control experiment for "what does a second
product actually cost", and everything below is something it paid for by hand
that the third product would otherwise pay again. Nothing here changes how a
token is validated.

### Added

- **The service provider now removes the authentication surface Laravel puts
  back.** Since Laravel 11 the framework recursively merges its own shipped
  `config/auth.php` into the application's, so a product with no `User` model and
  an almost-empty `config/auth.php` still resolves a session guard, an eloquent
  provider pointing at the deleted class, and a password-reset broker — none of
  which appear in the file a reviewer reads. A config file cannot delete a key
  the merge adds, so `Support\AuthConfigHardener` runs in `register()` and drops
  the entries that **cannot work**: an eloquent provider whose model class does
  not exist, then any guard or broker whose `provider` now dangles, then
  `auth.defaults.passwords` if its broker went. It never touches
  `auth.defaults.guard`, a guard with no `provider` key, or a `database`-driver
  provider, and it is a complete no-op on a product that still has a User model —
  which includes Coms Coupler for its whole soak period, where `web`, `api` and
  `providers.users` are deliberate because dual-accept is the rollback. What was
  removed is readable at `wollerp-auth.runtime.pruned_auth_config`, precisely
  because it is invisible in `config/auth.php` by construction.
  `WOLLERP_AUTH_HARDEN_AUTH_CONFIG=false` disables it.
- **`WOLLERP_SERVICE_SLUG` and `WOLLERP_AUTH_ISSUER` are asserted at boot.**
  `TokenValidator` already refused to construct without them, but it is a lazily
  resolved singleton, so a deploy missing one booted cleanly, answered `/up` with
  a 200, passed a smoke test and then failed for every real user. The container
  now refuses to finish booting, so the health check fails and the rollout halts
  on its own. In the console the assertion applies only to the deploy cache
  warmers and the long-running request servers
  (`Support\PlatformIdentity::ASSERTED_CONSOLE_COMMANDS`), so `vendor:publish`,
  `migrate` and `composer install`'s package discovery still work on a product
  that has not been configured yet — a package that cannot be installed before it
  is configured is a package the next product pays for again.
  `WOLLERP_AUTH_ASSERT_IDENTITY_ON_BOOT=false` disables it.
- **`Exceptions\UnconfiguredIdentityException`**, deliberately **not** a
  `WollerpAuthException`. That family is the per-request vocabulary a product
  maps onto 401 and 503; a missing `.env` line is neither, and a 401 would send
  every user back through login for a deployment defect.
- **`users_mirror` ships with the generated `id` column.** `auth_user_id` is the
  real primary key and `MirrorSynchroniser` writes it by name, so it cannot be
  renamed — but `id` is Laravel's default route key and `keyBy()` argument, so
  the first `where('id', …)` in any consumer was `Unknown column`. The migration
  stub now creates `id` as `virtualAs('auth_user_id')` with an index, guarded to
  the drivers whose grammar emits a real generated column (MySQL, MariaDB,
  SQLite). It is skipped elsewhere rather than silently created as an unusable
  NOT NULL column — SQL Server's grammar ignores `virtualAs()` instead of
  erroring. This used to be a hand-edit on the *published* file, which every
  consumer had to be told about and which `vendor:publish --force` undid.

### Changed

- **`DenylistChecker::revoke()` takes `mixed` and returns `bool`.** The
  documented handler forwards `$request->input(...)`, which returns whatever was
  in the JSON body, so under the platform's mandatory `declare(strict_types=1)`
  the previous `?string` signature turned `{"sid": 12345}` into a TypeError — a
  **500 on a service-plane call**, which the sender treats as retryable and
  re-delivers five more times. `sid`, `jti` and `reason` are now normalised the
  way `not_after` already was: an int is stringified and matched on, a non-scalar
  becomes null. The return value is `false` when the payload named neither a
  `sid` nor a `jti`, so the handler can answer 422 instead of telling the auth
  server a revocation it never performed had succeeded. Existing callers are
  unaffected — the parameter set and order are unchanged and the return was
  previously `void`.
- **The published migration stubs are Pint-clean** (`class_definition`,
  `braces_position`, `ordered_imports`, `fully_qualified_strict_types`,
  `line_ending`), and a scoped `.gitattributes` pins the published artefacts to
  LF. Without it, `core.autocrlf` on a Windows checkout hands a source install
  CRLF files that the consumer's own Pint run rewrites on its first CI run, and
  again after every republish.
- **`WOLLERP_AUTH_DB_CONNECTION` is documented for the common case.** The config
  comment said "For Coms Coupler that is `product_db`", from which a
  single-database product reasonably concluded it had to invent a second
  connection. The correct answer — leave it unset, and the package uses the
  default connection, migration ledger included — is now stated first, with Coms
  Coupler as the exception it is.
- **`INTEGRATION.md` is an integration guide again.** It was a Coms Coupler
  migration runbook, title included: for a greenfield product roughly half was
  inapplicable and nothing signposted which half. It is now a short generic guide
  covering registration, install, publish, guard, routes, the revoke handler,
  backfill and a nine-line verification checklist. The migration specifics — the
  88 files / 106 occurrences, the nine legacy `'id'` call sites with line
  numbers, the Passport soak, the phase-5 deletion list — moved to
  `INTEGRATION-coms-coupler.md`, which each document now points at from the top.
- **The route-protection recommendation is inverted: `wollerp.auth` by default,
  `auth:wollerp` only with a handler.** Laravel's own `Authenticate` reaches the
  guard through `Guard::check()`, and `TokenGuard::user()` correctly swallows
  `WollerpAuthException` and returns null because the `Guard` contract requires
  it — so a JWKS outage arrives at the client as a **401** when CONTRACT §3 says
  it is a 503, which is the exact failure the guide's own checklist demanded be a
  503. Products that want their own envelope are told the price: a
  `WollerpAuthException` render hook mapping `status()`, without which those
  checks cannot pass.
- **Registering an OAuth client against a product changes redirect-URI
  validation**, and that is now written down in both documents. Once `client_id`
  maps to a slug, validation reads the registry's URI list rather than the client
  row's, so registering the id without the URI 400s the authorize step before any
  code is issued — and the error looks like a redirect-URI typo when it is not.

### Tests

- 236 → 265, zero failures. New coverage: the auth-config hardener in both
  directions (it removes the merged-in surface; it is a no-op on Coms Coupler's
  shape), the boot assertion including that it does **not** break
  `vendor:publish`, `migrate` or `wollerp:conformance`, the generated `id` column
  against the real published stub on SQLite, and the malformed revocation
  payloads. No conformance assertion was weakened.

## [0.1.0] - 2026-09-16

First tagged release. Everything below is new; the package did not exist before.

Until this tag, the only way to install it was `dev-main`. `composer.lock` made
an individual install reproducible, but any `composer update` silently adopted
whatever happened to be on `main` — which is precisely the unreviewed deploy
§8 exists to prevent, on the one component that validates every token on the
estate. Consumers should move to `wollerp/auth-client:0.1.0`.

### Added

#### Token validation — CONTRACT §2, fully offline

- `Token\TokenValidator` performs the whole layer-1 pipeline: decode header,
  resolve `kid`, **pin `alg` to RS256**, verify the RSA signature, check
  `exp`/`nbf`/`iat`, exact-match `iss`, and check `aud` membership.
- The algorithm is a property of the verifier and is never read from the token
  to select a routine or a key type. There is deliberately **no** configuration
  key for it: `alg: none` and an HS256 token signed with the published RSA
  public key are both complete authentication bypasses against a verifier that
  trusts the header.
- `iss` is compared with `hash_equals` and never prefix- or suffix-matched.
- Leeway is **clamped** to 60 s rather than validated, so a bad config value
  degrades to the safe maximum instead of throwing. An unconfigured `issuer` or
  `audience` makes the validator refuse to construct.
- `Token\Claims` exposes the contract claims plus `authenticatedWithin()`, which
  answers the re-auth question from `auth_time` with no call to the auth server.

#### JWKS — CONTRACT §3

- `Jwks\JwksClient` resolves `kid → PEM`, converting and validating JWKs once at
  cache-write time. Only RSA keys declaring RS256 (or declaring nothing), with
  `use: sig` and a modulus of at least 2048 bits, are accepted; `oct` and `EC`
  entries are dropped rather than stored, because an `oct` entry reaching a
  verifier is how HMAC confusion attacks start.
- `Jwks\JwksCache` keeps a 6 h working copy and a long-lived last-known-good
  copy, so a JWKS outage is not an auth outage for keys already held.
- Forced refetches on an unknown `kid` are throttled, so unknown-kid traffic
  cannot be used to make a product hammer the auth server. A cold-cache fetch
  does not spend the throttle slot — that fetch *is* the fresh copy.
- A JWKS problem is a **503**, not a 401, with two distinct reasons:
  `jwks_unavailable` (unreachable, nothing cached or bundled) and
  `jwks_unusable` (reachable, publishing nothing we will trust).

#### Revocation — CONTRACT §2 layer 2, §6

- `Revocation\DenylistChecker` does one indexed local query per authenticated
  request. Local by design: a call to the auth server on every request would
  make it a hard dependency of every product's availability.
- `expires_at` is deliberately not in the predicate, so clock skew between the
  pruning host and the request host cannot resurrect a revoked session.
- `revoke()` is idempotent (the webhook is retried six times) and normalises the
  ISO-8601 `not_after` the auth server actually sends.

#### User mirror — CONTRACT §4

- `Mirror\MirroredUser` is a read-only projection with **no password column and
  no credential surface**, implementing `Authenticatable` so `$request->user()`
  keeps working in product code.
- The write guard overrides `save()`, `saveOrFail()` and `delete()` rather than
  using model events, because `saveQuietly()`, `deleteQuietly()` and
  `withoutEvents()` all suppress events — an event-based guard is bypassed by a
  one-word change.
- `Mirror\MirrorSynchroniser` upserts from a token (layer 1) or a sync record
  (layer 3) and never rolls a row backwards on a stale `ver`.

#### Framework integration

- `wollerp` guard driver (`Guard\TokenGuard`) so products write `auth:wollerp`.
  The guard runs layers 1 and 2 plus the mirror upsert on its own — a product
  must not have to remember to stack a second middleware for the guard to be
  real.
- `wollerp.auth` and `wollerp.hmac` middleware aliases.
- Publishable config (`wollerp-auth-config`) and migration stubs
  (`wollerp-auth-migrations`) for `users_mirror` and `revoked_tokens`.

#### Service plane — CONTRACT §5

- `Hmac\Signer` / `Hmac\Verifier` over `{timestamp}.{raw_body}`, with a replay
  window and an optional IP allowlist.
- `users:sync` for the initial backfill and the nightly reconcile (layer 3).

#### Conformance suite

- A conformance suite that generates a real 2048-bit RSA keypair at runtime and
  mints both genuine tokens and the exact forgeries an attacker would try — no
  fixtures, no checked-in keys, no dependency on the auth server being
  reachable.

### Changed

- **The conformance suite now ships in `src/` and runs inside a consumer.**
  INTEGRATION.md §8 check 1 told integrators to run
  `pest --testsuite=conformance` from their own application. That could not
  work: Composer never loads a dependency's `autoload-dev`, so this package's
  `tests/` directory is not on a product's autoloader, and the harness needed
  `orchestra/testbench` — a dev dependency a product has no reason to install.
  A gate that cannot run is a gate that is skipped.

  The assertions now live in `Conformance\ConformanceSuite` with no
  test-framework dependency, and are exposed three ways:

  - `php artisan wollerp:conformance --strict` — nothing to install, nothing to
    publish, works with a warm `config:cache`, exits non-zero on failure;
  - `app(ConformanceSuite::class)->run(strict: true)->passed()` — one line in a
    product's own Pest or PHPUnit suite;
  - `--json` for a pipeline to parse.

  41 checks run against a `TokenValidator` built from the consumer's **real**
  `issuer`, `audience`, `leeway` and length limit, plus wiring checks against
  the live guard, middleware aliases, denylist connection and mirror. It makes
  no network calls and never touches the real JWKS cache, so it is safe to run
  on a production host.

  A 42nd check, `suite.integrity`, asserts that the checks which executed are
  exactly those the manifest declares, and that every id in `BYPASS_GUARDS` is
  still present. Deleting a check fails the run rather than shortening it.

- `Tests\Support\TokenFactory` now extends `Conformance\TokenForge`, so the
  package tests itself against the same forgeries it tests a product against.
  If those two drifted, only one of them would be the real gate.

- `jwks.bundled_keys` can be populated from `WOLLERP_AUTH_BUNDLED_JWKS`, which
  accepts a JWKS document, a bare list of JWKs or a single JWK, as raw JSON or
  base64. It shipped empty with no documented way to fill it other than editing
  a published config file by hand, which meant in practice it stayed empty — and
  an empty bundle turns a JWKS outage on a cold cache into a 503 for the whole
  product. An unparsable value degrades to the previous behaviour and never
  throws out of a config file. This is not a trust escalation: a bundled key
  still has to match the token's `kid` and verify the signature, and anyone who
  can set this variable can already repoint `WOLLERP_AUTH_ISSUER`.

### Fixed

Three defects found between the first push to `main` and this tag, all by
exercising the package inside a real consumer rather than by its own suite —
which passed throughout.

- **`Hmac\Signer` refused to construct without a secret**, which broke
  `php artisan list` and `php artisan tinker` on any consumer not yet issued
  `WOLLERP_HMAC_SECRET_AUTH`. The class is a singleton injected into
  `SyncUsersCommand`, and `#[AsCommand]` defers *targeted invocation* but not
  *enumeration* — anything reaching `Application::all()` constructed it and died
  at console boot. That included the `tinker` check INTEGRATION.md §3 tells
  integrators to run to verify their install. The guard moved into
  `sign()`/`headers()`: signing with an empty secret or project is still
  impossible, merely existing unconfigured is not.

- **`Revocation\DenylistChecker` used `date()` where it needed `gmdate()`**, in
  four places. Under a consumer configured for `Europe/London` that writes BST
  wall-clock into `expires_at`, so across a DST transition `prune()` could
  delete a revocation up to an hour early — putting a revoked token back in
  service inside its 15-minute TTL, which is exactly the window layer 2 exists
  to close. Measured at a one-hour skew on a BST date.

- **The published migration stubs set `Schema::connection()` but not
  `getConnection()`.** Laravel resolves the migrations *ledger* from the latter,
  so on a multi-database consumer the tables land on the configured connection
  while the ledger row is written to the default one. The migration then reports
  as never-run and is attempted again on the next deploy. Coms Coupler runs two
  databases with a ledger each, so this would have bitten on the first deploy.

### Security

- The algorithm is pinned to RS256 in the verifier and is not configurable.
  Reintroducing an `algorithm` config key, or dispatching on the header's `alg`,
  is a total authentication bypass — the RSA public key is published for anyone
  to fetch, so an attacker who chooses the algorithm holds the "secret".
- The package ships **no default `audience`**. CONTRACT §7 keeps the product
  registry open, and a baked-in default would mean a mis-deployed backend
  silently announces itself as another product and accepts that product's
  tokens. Unset is an error, not an empty comparison.
- The mirror has no password column and every write path through the model
  throws. The residual risk is a raw query-builder write, which nothing in PHP
  can intercept; the table is named for what it is.

[Unreleased]: https://github.com/lumicorelabs/wollerp-auth-client/compare/0.1.0...HEAD
[0.1.0]: https://github.com/lumicorelabs/wollerp-auth-client/releases/tag/0.1.0
