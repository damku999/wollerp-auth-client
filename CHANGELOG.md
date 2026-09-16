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
