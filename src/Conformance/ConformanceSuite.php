<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Conformance;

use Closure;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Routing\Router;
use Throwable;
use Wollerp\AuthClient\Exceptions\MirrorWriteForbiddenException;
use Wollerp\AuthClient\Exceptions\WollerpAuthException;
use Wollerp\AuthClient\Guard\TokenGuard;
use Wollerp\AuthClient\Http\Middleware\Authenticate;
use Wollerp\AuthClient\Http\Middleware\VerifyHmacSignature;
use Wollerp\AuthClient\Jwks\JwksCache;
use Wollerp\AuthClient\Jwks\JwksClient;
use Wollerp\AuthClient\Revocation\DenylistChecker;
use Wollerp\AuthClient\Token\Claims;
use Wollerp\AuthClient\Token\TokenValidator;

/**
 * The conformance suite, shipped in `src/` so it runs inside a consumer.
 *
 * ── Why this is not a Pest test suite ────────────────────────────────────────
 * INTEGRATION.md used to tell integrators to run `pest --testsuite=conformance`
 * from inside their own application. That could not work: Composer never loads
 * a dependency's `autoload-dev`, so the package's `tests/` directory is simply
 * not on a consumer's autoloader, and the harness needed `orchestra/testbench`
 * — a dev dependency a product has no reason to install.
 *
 * The fix is to ship the assertions rather than the test files. This class has
 * no test-framework dependency at all, which means:
 *
 *   • `php artisan wollerp:conformance` runs it with nothing else installed,
 *     including on a production host with `config:cache` warm;
 *   • a product's own test suite asserts it in one line, no testbench, no
 *     bootstrap to publish, no second package to install;
 *   • a deploy pipeline can gate on the exit code.
 *
 * ── What it actually verifies ────────────────────────────────────────────────
 * The PIN checks run against a TokenValidator built from the consumer's REAL
 * `issuer`, `audience`, `leeway` and `max_length` — the live, possibly
 * config-cached values — but with an ephemeral keypair minted in-process. That
 * catches things the package's own suite structurally cannot: this product's
 * OpenSSL build, this product's `WOLLERP_SERVICE_SLUG`, this product's cached
 * config. No network, no auth server, no production signing key.
 *
 * The WIRING checks interrogate the live application: the guard driver, the
 * middleware aliases, the denylist table on its configured connection, and the
 * mirror's write guard.
 *
 * ── Why a check cannot be quietly dropped ────────────────────────────────────
 * CHECKS below is the manifest, and run() asserts that the set of checks that
 * actually executed is exactly the set declared in it. Deleting a method makes
 * the run fail on `suite.integrity` rather than silently getting shorter, and
 * the package's own test suite pins both the manifest size and every id in the
 * bypass-guarding subset. Weakening the suite is therefore itself a failure,
 * in both the package and every consumer running it.
 */
final class ConformanceSuite
{
    /** PIN severity is fatal everywhere, with no flag to downgrade it. */
    private const PIN = CheckResult::PIN;

    /** POSTURE warns by default; `--strict` promotes it to a failure. */
    private const POSTURE = CheckResult::POSTURE;

    /**
     * The manifest. One entry per check, in execution order.
     *
     * @var list<array{id: string, group: string, severity: string, title: string, guards: string, method: string}>
     */
    public const CHECKS = [
        // ── Algorithm pinning. CONTRACT §2 step 3. ──────────────────────────
        [
            'id' => 'pin.alg.hs256_signed_with_public_key',
            'group' => 'algorithm',
            'severity' => self::PIN,
            'title' => 'An HS256 token keyed with the RSA public key is refused',
            'guards' => 'Algorithm confusion. The public key is published at the JWKS endpoint for anyone to fetch, so a verifier that dispatches on the header lets an attacker mint any token for any user with no credentials at all.',
            'method' => 'checkAlgorithmConfusion',
        ],
        [
            'id' => 'pin.alg.hs256_privilege_escalation',
            'group' => 'algorithm',
            'severity' => self::PIN,
            'title' => 'An HS256 forgery naming another user is refused',
            'guards' => 'The same attack aimed at a specific account rather than at the mechanism.',
            'method' => 'checkAlgorithmConfusionEscalation',
        ],
        [
            'id' => 'pin.alg.none_empty_signature',
            'group' => 'algorithm',
            'severity' => self::PIN,
            'title' => '`alg: none` with an empty signature is refused',
            'guards' => 'The oldest JWT bypass there is: a verifier that honours the header skips signature verification entirely.',
            'method' => 'checkAlgNoneEmptySignature',
        ],
        [
            'id' => 'pin.alg.none_junk_signature',
            'group' => 'algorithm',
            'severity' => self::PIN,
            'title' => '`alg: none` carrying a junk signature is refused',
            'guards' => 'An implementation that only rejects an EMPTY signature segment.',
            'method' => 'checkAlgNoneJunkSignature',
        ],
        [
            'id' => 'pin.alg.none_case_variants',
            'group' => 'algorithm',
            'severity' => self::PIN,
            'title' => 'Capitalisation and whitespace variants of `none` are refused',
            'guards' => 'A case-insensitive or trimmed comparison against a denylist of algorithm names.',
            'method' => 'checkAlgNoneCaseVariants',
        ],
        [
            'id' => 'pin.alg.header_absent',
            'group' => 'algorithm',
            'severity' => self::PIN,
            'title' => 'A header with no `alg` at all is refused',
            'guards' => 'A missing algorithm defaulting to "whatever the key happens to be".',
            'method' => 'checkAlgHeaderAbsent',
        ],
        [
            'id' => 'pin.alg.every_other_jose_label',
            'group' => 'algorithm',
            'severity' => self::PIN,
            'title' => 'Every other JOSE algorithm label is refused',
            'guards' => 'An allowlist wider than the single string RS256 — including the case and whitespace variants of RS256 itself.',
            'method' => 'checkEveryOtherAlgorithmLabel',
        ],

        // ── Signature verification. CONTRACT §2 step 4. ─────────────────────
        [
            'id' => 'pin.signature.single_byte_flip',
            'group' => 'signature',
            'severity' => self::PIN,
            'title' => 'A signature altered by one byte is refused',
            'guards' => 'Signature verification actually happening, rather than being short-circuited.',
            'method' => 'checkTamperedSignature',
        ],
        [
            'id' => 'pin.signature.payload_swapped',
            'group' => 'signature',
            'severity' => self::PIN,
            'title' => 'A swapped payload under a valid signature is refused',
            'guards' => 'The naive "just edit the claims" forgery, and any verifier that reads claims before verifying.',
            'method' => 'checkSwappedPayload',
        ],
        [
            'id' => 'pin.signature.foreign_key_same_kid',
            'group' => 'signature',
            'severity' => self::PIN,
            'title' => 'A token signed by an impostor key claiming the same `kid` is refused',
            'guards' => 'Trusting the `kid` label instead of the key material it resolves to.',
            'method' => 'checkForeignKeySameKid',
        ],
        [
            'id' => 'pin.signature.unknown_kid',
            'group' => 'signature',
            'severity' => self::PIN,
            'title' => 'A token naming an unpublished `kid` is refused',
            'guards' => 'CONTRACT §3. A `kid` in neither the current nor the previous key is a forgery or a long-rotated key.',
            'method' => 'checkUnknownKid',
        ],
        [
            'id' => 'pin.structure.kid_absent',
            'group' => 'signature',
            'severity' => self::PIN,
            'title' => 'A header with no `kid` is refused',
            'guards' => '"No kid" resolving to "any published key", which makes rotation a forgery window.',
            'method' => 'checkMissingKid',
        ],

        // ── Issuer. CONTRACT §2 step 6, §1 "exact-match only". ──────────────
        [
            'id' => 'pin.claims.issuer_mismatch',
            'group' => 'issuer',
            'severity' => self::PIN,
            'title' => 'A token from a different issuer is refused',
            'guards' => 'Any other identity provider being able to mint tokens this product honours.',
            'method' => 'checkIssuerMismatch',
        ],
        [
            'id' => 'pin.claims.issuer_lookalikes',
            'group' => 'issuer',
            'severity' => self::PIN,
            'title' => 'Issuer lookalikes a non-exact comparison would admit are refused',
            'guards' => 'str_starts_with() accepting "{issuer}.attacker.example"; str_contains() accepting the issuer buried in a path.',
            'method' => 'checkIssuerLookalikes',
        ],
        [
            'id' => 'pin.claims.issuer_absent',
            'group' => 'issuer',
            'severity' => self::PIN,
            'title' => 'A token with no `iss` claim is refused',
            'guards' => 'An absent issuer comparing equal to an unset expectation.',
            'method' => 'checkIssuerAbsent',
        ],

        // ── Audience. CONTRACT §2 step 7, §7. ───────────────────────────────
        [
            'id' => 'pin.claims.audience_mismatch',
            'group' => 'audience',
            'severity' => self::PIN,
            'title' => 'A token audienced to a different product is refused',
            'guards' => 'Lateral movement. A token for any other product in the estate opening a session here.',
            'method' => 'checkAudienceMismatch',
        ],
        [
            'id' => 'pin.claims.audience_lookalikes',
            'group' => 'audience',
            'severity' => self::PIN,
            'title' => 'Audience values that only look like this service are refused',
            'guards' => 'Case-folded, trimmed, substring or comma-joined audience matching.',
            'method' => 'checkAudienceLookalikes',
        ],
        [
            'id' => 'pin.claims.audience_empty_array',
            'group' => 'audience',
            'severity' => self::PIN,
            'title' => 'An empty `aud` array is refused',
            'guards' => '"Audienced to nobody" being read as "audienced to everybody".',
            'method' => 'checkAudienceEmptyArray',
        ],
        [
            'id' => 'pin.claims.audience_absent',
            'group' => 'audience',
            'severity' => self::PIN,
            'title' => 'A token with no `aud` claim is refused',
            'guards' => 'An absent audience skipping the check rather than failing it.',
            'method' => 'checkAudienceAbsent',
        ],

        // ── Temporal. CONTRACT §2 step 5. ───────────────────────────────────
        [
            'id' => 'pin.temporal.expired_outside_leeway',
            'group' => 'temporal',
            'severity' => self::PIN,
            'title' => 'A token past `exp` beyond the leeway window is refused',
            'guards' => 'The 15 minute TTL is the backstop of the whole revocation design; if expiry does not bite, a dropped revocation webhook means a session that never ends.',
            'method' => 'checkExpiredOutsideLeeway',
        ],
        [
            'id' => 'pin.temporal.accepted_inside_leeway',
            'group' => 'temporal',
            'severity' => self::PIN,
            'title' => 'A token expired within the leeway window is still accepted',
            'guards' => 'The other direction: a leeway of zero turns ordinary clock drift into intermittent 401s across the estate.',
            'method' => 'checkAcceptedInsideLeeway',
        ],
        [
            'id' => 'pin.temporal.not_yet_valid',
            'group' => 'temporal',
            'severity' => self::PIN,
            'title' => 'A token whose `nbf` is in the future is refused',
            'guards' => 'A pre-minted token becoming usable before the issuer intended.',
            'method' => 'checkNotYetValid',
        ],
        [
            'id' => 'pin.temporal.issued_in_future',
            'group' => 'temporal',
            'severity' => self::PIN,
            'title' => 'A token whose `iat` is in the future is refused',
            'guards' => 'The same, via the claim an implementation is most likely to skip.',
            'method' => 'checkIssuedInFuture',
        ],
        [
            'id' => 'pin.temporal.leeway_capped',
            'group' => 'temporal',
            'severity' => self::PIN,
            'title' => 'Configured leeway is clamped to the contract maximum',
            'guards' => 'CONTRACT §2 caps leeway at 60s. It is the knob an operator reaches for when a clock problem causes 401s, and widening it to an hour extends the life of every revoked and expired token in the estate by an hour.',
            'method' => 'checkLeewayCapped',
        ],

        // ── Structure and required claims. ──────────────────────────────────
        [
            'id' => 'pin.claims.required_absent',
            'group' => 'structure',
            'severity' => self::PIN,
            'title' => 'A token missing any required claim is refused',
            'guards' => 'Identity (sub/uid), revocation targets (jti/sid) and mirror version (ver) all being optional — a token with no `sid` cannot be revoked.',
            'method' => 'checkRequiredClaimsAbsent',
        ],
        [
            'id' => 'pin.structure.malformed',
            'group' => 'structure',
            'severity' => self::PIN,
            'title' => 'Structurally broken tokens are refused',
            'guards' => 'Segment-count and base64url strictness, ahead of any crypto.',
            'method' => 'checkMalformedTokens',
        ],
        [
            'id' => 'pin.structure.oversized',
            'group' => 'structure',
            'severity' => self::PIN,
            'title' => 'An oversized token is refused before any crypto runs',
            'guards' => 'CPU exhaustion from unbounded input reaching the verifier.',
            'method' => 'checkOversizedToken',
        ],

        // ── The happy path, and what must NOT be in a token. ────────────────
        [
            'id' => 'pin.accepts.valid_token',
            'group' => 'accepts',
            'severity' => self::PIN,
            'title' => 'A well-formed RS256 token is accepted and exposes its claims',
            'guards' => 'The suite failing everything for the wrong reason. Without this, a validator that rejects unconditionally would score full marks.',
            'method' => 'checkValidTokenAccepted',
        ],
        [
            'id' => 'pin.accepts.audience_string_normalised',
            'group' => 'accepts',
            'severity' => self::PIN,
            'title' => 'A bare-string `aud` is normalised rather than rejected',
            'guards' => 'RFC 7519 permits a bare string; refusing it would turn an issuer-side formatting change into an estate-wide outage.',
            'method' => 'checkAudienceStringNormalised',
        ],
        [
            'id' => 'pin.accepts.no_authorisation_claims',
            'group' => 'accepts',
            'severity' => self::PIN,
            'title' => 'No authorisation claim is exposed from the token',
            'guards' => 'CONTRACT §1 "absent by design". A token carrying roles, plan or profile is a stale authority cache with a 15 minute lifetime.',
            'method' => 'checkNoAuthorisationClaims',
        ],

        // ── Wiring, against the live application. ───────────────────────────
        [
            'id' => 'wiring.config.audience_configured',
            'group' => 'wiring',
            'severity' => self::PIN,
            'title' => '`wollerp-auth.audience` is set to this product\'s registry slug',
            'guards' => 'CONTRACT §7. The registry is open so the package ships no default; a backend that does not know which product it is cannot decide whose tokens it accepts.',
            'method' => 'checkAudienceConfigured',
        ],
        [
            'id' => 'wiring.config.issuer_configured',
            'group' => 'wiring',
            'severity' => self::PIN,
            'title' => '`wollerp-auth.issuer` is configured',
            'guards' => 'An empty issuer turning the exact-match check into "compare against nothing".',
            'method' => 'checkIssuerConfigured',
        ],
        [
            'id' => 'wiring.guard.driver_resolves',
            'group' => 'wiring',
            'severity' => self::PIN,
            'title' => 'The configured guard resolves to the Wollerp TokenGuard',
            'guards' => 'A route group still on the old guard, or `config/auth.php` missing the guard entry, which makes `auth:wollerp` throw at request time instead of at deploy time.',
            'method' => 'checkGuardDriverResolves',
        ],
        [
            'id' => 'wiring.middleware.aliases_registered',
            'group' => 'wiring',
            'severity' => self::PIN,
            'title' => 'The `wollerp.auth` and `wollerp.hmac` middleware aliases are registered',
            'guards' => 'A route referencing an alias that does not exist, or one shadowed by a product-defined alias of the same name.',
            'method' => 'checkMiddlewareAliases',
        ],
        [
            'id' => 'wiring.denylist.revocation_bites',
            'group' => 'wiring',
            'severity' => self::PIN,
            'title' => 'A revoked `sid` is matched by the denylist on its configured connection',
            'guards' => 'CONTRACT §2 layer 2. Proves the table exists on the connection the checker actually resolved. If this is wrong, logout and reuse detection do nothing for the remaining life of every issued token. Runs inside a transaction that is rolled back.',
            'method' => 'checkRevocationBites',
        ],
        [
            'id' => 'wiring.mirror.no_password_column',
            'group' => 'wiring',
            'severity' => self::PIN,
            'title' => 'The mirror table has no credential columns',
            'guards' => 'CONTRACT §4. The product database must never be capable of authenticating anyone.',
            'method' => 'checkMirrorHasNoCredentialColumns',
        ],
        [
            'id' => 'wiring.mirror.write_guard_throws',
            'group' => 'wiring',
            'severity' => self::PIN,
            'title' => 'A write to the mirror outside the synchroniser throws',
            'guards' => 'The mirror drifting from the auth server because product code edited it directly. Runs inside a transaction that is rolled back.',
            'method' => 'checkMirrorWriteGuard',
        ],
        [
            'id' => 'wiring.jwks.bundled_keys_usable',
            'group' => 'wiring',
            'severity' => self::PIN,
            'title' => 'Every configured bundled key converts to a usable RS256 key',
            'guards' => 'A typo\'d or truncated bundle is worse than an empty one: the cold-start fallback looks configured and is not. Skipped when none are configured.',
            'method' => 'checkBundledKeysUsable',
        ],

        // ── Posture. Warns by default; `--strict` makes these fatal. ────────
        [
            'id' => 'posture.jwks.bundled_keys_present',
            'group' => 'posture',
            'severity' => self::POSTURE,
            'title' => '`jwks.bundled_keys` is populated',
            'guards' => 'INTEGRATION.md §8 check 10. With an empty bundle, a JWKS outage on a cold cache is a 503 across the whole product rather than a degraded-but-serving start.',
            'method' => 'checkBundledKeysPresent',
        ],
        [
            'id' => 'posture.jwks.url_matches_issuer',
            'group' => 'posture',
            'severity' => self::POSTURE,
            'title' => 'The JWKS URL is on the issuer\'s origin',
            'guards' => 'A JWKS URL pointing somewhere other than the issuer means key material and identity come from different places — usually a stale override left behind from a staging environment.',
            'method' => 'checkJwksUrlMatchesIssuer',
        ],
        [
            'id' => 'posture.hmac.inbound_controls',
            'group' => 'posture',
            'severity' => self::POSTURE,
            'title' => 'The service plane has an inbound secret configured',
            'guards' => 'CONTRACT §5. With no inbound secret the revocation webhook cannot be verified, so layer 2 is fed by nothing and logout stops propagating.',
            'method' => 'checkServicePlaneControls',
        ],
    ];

    /**
     * The subset that guards a complete authentication bypass. The package's
     * own test suite asserts every one of these is present in CHECKS, so they
     * cannot be removed without the package going red.
     *
     * @var list<string>
     */
    public const BYPASS_GUARDS = [
        'pin.alg.hs256_signed_with_public_key',
        'pin.alg.hs256_privilege_escalation',
        'pin.alg.none_empty_signature',
        'pin.alg.none_junk_signature',
        'pin.alg.none_case_variants',
        'pin.alg.header_absent',
        'pin.alg.every_other_jose_label',
        'pin.signature.single_byte_flip',
        'pin.signature.payload_swapped',
        'pin.signature.foreign_key_same_kid',
        'pin.signature.unknown_kid',
        'pin.claims.issuer_mismatch',
        'pin.claims.issuer_lookalikes',
        'pin.claims.audience_mismatch',
        'pin.claims.audience_lookalikes',
        'pin.temporal.expired_outside_leeway',
        'pin.temporal.leeway_capped',
        'wiring.config.audience_configured',
        'wiring.denylist.revocation_bites',
    ];

    /** Claims a token must never carry. CONTRACT §1. */
    private const FORBIDDEN_CLAIMS = [
        'roles', 'permissions', 'subscription', 'plan', 'modules',
        'active_profile_type', 'company_id', 'client_id', 'professional_id',
    ];

    private ?TokenValidator $validator = null;

    private ?TokenForge $forge = null;

    /**
     * Lazy factories rather than resolved instances: constructing a
     * DenylistChecker opens a database connection, and the suite must be
     * cheap enough to bind unconditionally in the service provider.
     *
     * @param  (Closure(): DenylistChecker)|null  $denylist
     * @param  (Closure(): Model)|null  $mirrorModel
     * @param  (Closure(): ConnectionInterface)|null  $denylistConnection
     */
    public function __construct(
        private readonly ConfigRepository $config,
        private readonly ?AuthFactory $auth = null,
        private readonly ?Router $router = null,
        private readonly ?Closure $denylist = null,
        private readonly ?Closure $mirrorModel = null,
        private readonly ?Closure $denylistConnection = null,
    ) {}

    /**
     * @param  bool  $strict  Promote posture warnings to failures.
     */
    public function run(bool $strict = false): Report
    {
        $this->validator = null;
        $this->forge = null;

        $results = [];

        foreach (self::CHECKS as $check) {
            $results[] = $this->execute($check);
        }

        $results[] = $this->integrityResult($results);

        return new Report(
            $results,
            $strict,
            (string) $this->config->get('wollerp-auth.issuer', ''),
            (string) $this->config->get('wollerp-auth.audience', ''),
        );
    }

    /**
     * @param  array{id: string, group: string, severity: string, title: string, guards: string, method: string}  $check
     */
    private function execute(array $check): CheckResult
    {
        if (! method_exists($this, $check['method'])) {
            return CheckResult::fail($check, sprintf(
                'The manifest declares %s() but no such method exists. A check has been '
                .'removed or renamed without updating CHECKS.',
                $check['method'],
            ));
        }

        try {
            /** @var string $detail */
            $detail = $this->{$check['method']}() ?? '';

            return CheckResult::pass($check, $detail);
        } catch (CheckSkipped $skipped) {
            if ($check['severity'] === self::PIN && $check['group'] !== 'wiring') {
                return CheckResult::fail($check, 'A pin check attempted to skip: '.$skipped->getMessage());
            }

            return CheckResult::skip($check, $skipped->getMessage());
        } catch (CheckFailed $failed) {
            return CheckResult::fail($check, $failed->getMessage());
        } catch (Throwable $error) {
            return CheckResult::fail($check, sprintf(
                '%s: %s',
                $error::class,
                $error->getMessage(),
            ));
        }
    }

    /**
     * The anti-thinning gate. Compares what ran against what the manifest
     * declares, so a deleted or duplicated check is a loud failure rather than
     * a quietly shorter run.
     *
     * @param  list<CheckResult>  $results
     */
    private function integrityResult(array $results): CheckResult
    {
        $check = [
            'id' => 'suite.integrity',
            'group' => 'suite',
            'severity' => self::PIN,
            'title' => 'The suite that just ran is the suite the manifest declares',
            'guards' => 'A conformance run that passes because checks were removed. Every bypass this suite exists to catch is also a thing somebody could be tempted to delete when it goes red.',
        ];

        $declared = array_column(self::CHECKS, 'id');
        $executed = array_map(fn (CheckResult $result): string => $result->id, $results);

        $missing = array_values(array_diff($declared, $executed));
        $duplicated = array_values(array_diff_assoc($declared, array_unique($declared)));

        if ($missing !== []) {
            return CheckResult::fail($check, 'Declared but never executed: '.implode(', ', $missing));
        }

        if ($duplicated !== []) {
            return CheckResult::fail($check, 'Duplicate ids in the manifest: '.implode(', ', $duplicated));
        }

        $absent = array_values(array_diff(self::BYPASS_GUARDS, $declared));

        if ($absent !== []) {
            return CheckResult::fail($check, sprintf(
                'These guard a complete authentication bypass and are no longer in the manifest: %s',
                implode(', ', $absent),
            ));
        }

        return CheckResult::pass($check, sprintf(
            '%d checks declared, %d executed, %d of them guarding a bypass.',
            count($declared),
            count($executed),
            count(self::BYPASS_GUARDS),
        ));
    }

    // ── Algorithm pinning ────────────────────────────────────────────────────

    private function checkAlgorithmConfusion(): string
    {
        $this->assertRejected(
            $this->forge()->hs256WithPublicKey($this->forge()->payload()),
            'token_algorithm_not_allowed',
        );

        return 'HS256 keyed with the published RSA public key refused.';
    }

    private function checkAlgorithmConfusionEscalation(): string
    {
        $this->assertRejected(
            $this->forge()->hs256WithPublicKey($this->forge()->payload([
                'sub' => '01CONFORMANCEADMIN00000000',
                'uid' => 1,
                'email' => 'admin@invalid',
            ])),
            'token_algorithm_not_allowed',
        );

        return 'An HS256 forgery claiming uid 1 refused.';
    }

    private function checkAlgNoneEmptySignature(): string
    {
        $this->assertRejected(
            $this->forge()->algNone($this->forge()->payload()),
            'token_algorithm_not_allowed',
        );

        return '`alg: none` refused.';
    }

    private function checkAlgNoneJunkSignature(): string
    {
        $this->assertRejected(
            $this->forge()->algNone($this->forge()->payload(), 'bm90LWEtc2lnbmF0dXJl'),
            'token_algorithm_not_allowed',
        );

        return '`alg: none` with a non-empty signature segment refused.';
    }

    private function checkAlgNoneCaseVariants(): string
    {
        foreach (['None', 'NONE', 'nOnE', 'none '] as $variant) {
            $this->assertRejected(
                $this->forge()->hs256WithPublicKey($this->forge()->payload(), $variant),
                'token_algorithm_not_allowed',
                sprintf('alg "%s"', $variant),
            );
        }

        return '4 variants refused.';
    }

    private function checkAlgHeaderAbsent(): string
    {
        $this->assertRejected(
            $this->forge()->withoutAlgHeader($this->forge()->payload()),
            'token_algorithm_not_allowed',
        );

        return 'A header with no `alg`, over a genuine RS256 signature, refused.';
    }

    private function checkEveryOtherAlgorithmLabel(): string
    {
        $labels = ['HS256', 'HS384', 'HS512', 'RS384', 'RS512', 'PS256', 'PS384', 'ES256', 'ES384', 'EdDSA', 'rs256', 'RS256 ', ' RS256'];

        foreach ($labels as $label) {
            $this->assertRejected(
                $this->forge()->hs256WithPublicKey($this->forge()->payload(), $label),
                'token_algorithm_not_allowed',
                sprintf('alg "%s"', $label),
            );
        }

        return count($labels).' labels refused; only the exact string RS256 is accepted.';
    }

    // ── Signature ────────────────────────────────────────────────────────────

    private function checkTamperedSignature(): string
    {
        $this->assertRejected(
            $this->forge()->tamperSignature($this->forge()->sign($this->forge()->payload())),
            'token_signature_invalid',
        );

        return 'A one-byte signature flip refused.';
    }

    private function checkSwappedPayload(): string
    {
        $original = $this->forge()->sign($this->forge()->payload());

        $this->assertRejected(
            $this->forge()->tamperPayload($original, $this->forge()->payload([
                'uid' => 1,
                'sub' => '01CONFORMANCEADMIN00000000',
            ])),
            'token_signature_invalid',
        );

        return 'An escalated payload under the original signature refused.';
    }

    private function checkForeignKeySameKid(): string
    {
        $impostor = new TokenForge(
            $this->forge()->issuer,
            $this->forge()->audience,
            $this->forge()->kid,
        );

        $this->assertRejected(
            $impostor->sign($impostor->payload()),
            'token_signature_invalid',
        );

        return 'A different private key behind the same `kid` refused.';
    }

    private function checkUnknownKid(): string
    {
        $impostor = new TokenForge(
            $this->forge()->issuer,
            $this->forge()->audience,
            'wollerp-conformance-never-published',
        );

        $this->assertRejected(
            $impostor->sign($impostor->payload()),
            'token_signing_key_unknown',
        );

        return 'An unpublished `kid` refused as unknown, not as a bad signature.';
    }

    private function checkMissingKid(): string
    {
        $this->assertRejected(
            $this->forge()->sign($this->forge()->payload(), ['kid' => null]),
            'token_malformed',
        );

        return 'A header with no `kid` refused.';
    }

    // ── Issuer ───────────────────────────────────────────────────────────────

    private function checkIssuerMismatch(): string
    {
        $this->assertRejected(
            $this->forge()->sign($this->forge()->payload(['iss' => 'https://auth.someone-else.example'])),
            'token_issuer_mismatch',
        );

        return 'A foreign issuer refused, over a genuine signature.';
    }

    private function checkIssuerLookalikes(): string
    {
        $issuer = $this->forge()->issuer;

        $lookalikes = [
            $issuer.'.attacker.example',
            'https://attacker.example/'.$issuer,
            $issuer.'/',
            str_replace('https://', 'http://', $issuer),
            strtoupper($issuer),
            $issuer.'/realms/other',
            ' '.$issuer,
            $issuer.' ',
        ];

        foreach (array_unique($lookalikes) as $lookalike) {
            if ($lookalike === $issuer) {
                continue;
            }

            $this->assertRejected(
                $this->forge()->sign($this->forge()->payload(['iss' => $lookalike])),
                'token_issuer_mismatch',
                sprintf('iss "%s"', $lookalike),
            );
        }

        return 'Suffix, prefix, trailing slash, scheme downgrade, case change, path and whitespace variants all refused.';
    }

    private function checkIssuerAbsent(): string
    {
        $this->assertRejected(
            $this->forge()->sign($this->forge()->payload(remove: ['iss'])),
            'token_claims_invalid',
        );

        return 'A token with no `iss` refused.';
    }

    // ── Audience ─────────────────────────────────────────────────────────────

    private function checkAudienceMismatch(): string
    {
        $this->assertRejected(
            $this->forge()->sign($this->forge()->payload(['aud' => ['wollerp-conformance-other-product']])),
            'token_audience_mismatch',
        );

        return "A token for another product refused by `{$this->forge()->audience}`.";
    }

    private function checkAudienceLookalikes(): string
    {
        $audience = $this->forge()->audience;

        $lookalikes = [
            strtoupper($audience),
            strtolower($audience),
            $audience.' ',
            ' '.$audience,
            $audience.$audience,
            $audience.',other',
            substr($audience, 0, max(1, strlen($audience) - 1)),
        ];

        $tested = 0;

        foreach (array_unique($lookalikes) as $lookalike) {
            // A single-character or already-lowercase slug makes some of these
            // collapse onto the real value; comparing it would assert that the
            // correct audience is rejected.
            if ($lookalike === $audience || $lookalike === '') {
                continue;
            }

            $this->assertRejected(
                $this->forge()->sign($this->forge()->payload(['aud' => [$lookalike]])),
                'token_audience_mismatch',
                sprintf('aud "%s"', $lookalike),
            );

            $tested++;
        }

        if ($tested === 0) {
            throw new CheckFailed(sprintf(
                'No lookalike of the configured audience "%s" was distinguishable from it; '
                .'this check could not prove anything.',
                $audience,
            ));
        }

        return "{$tested} near-miss audience values refused.";
    }

    private function checkAudienceEmptyArray(): string
    {
        $this->assertRejected(
            $this->forge()->sign($this->forge()->payload(['aud' => []])),
            'token_audience_mismatch',
        );

        return 'An empty `aud` array refused.';
    }

    private function checkAudienceAbsent(): string
    {
        $this->assertRejected(
            $this->forge()->sign($this->forge()->payload(remove: ['aud'])),
            'token_claims_invalid',
        );

        return 'A token with no `aud` refused.';
    }

    // ── Temporal ─────────────────────────────────────────────────────────────

    private function checkExpiredOutsideLeeway(): string
    {
        $beyond = $this->validator()->leeway + 30;

        $this->assertRejected(
            $this->forge()->sign($this->forge()->payload(['exp' => time() - $beyond])),
            'token_expired',
        );

        return "A token {$beyond}s past `exp` refused.";
    }

    private function checkAcceptedInsideLeeway(): string
    {
        $leeway = $this->validator()->leeway;

        if ($leeway === 0) {
            // Zero is a legitimate if unforgiving choice. It still has to be
            // honoured exactly rather than quietly ignored, so assert the other
            // edge instead of skipping.
            $this->assertRejected(
                $this->forge()->sign($this->forge()->payload(['exp' => time() - 5])),
                'token_expired',
            );

            return 'Leeway is 0 and honoured exactly: a token 5s past `exp` is refused.';
        }

        $inside = intdiv($leeway, 2);

        $this->assertAccepted(
            $this->forge()->sign($this->forge()->payload(['exp' => time() - $inside])),
        );

        return "A token {$inside}s past `exp` is still accepted inside the {$leeway}s window.";
    }

    private function checkNotYetValid(): string
    {
        $ahead = $this->validator()->leeway + 30;

        $this->assertRejected(
            $this->forge()->sign($this->forge()->payload([
                'nbf' => time() + $ahead,
                'iat' => time() + $ahead,
                'exp' => time() + $ahead + 900,
            ])),
            'token_not_yet_valid',
        );

        return "A token with `nbf` {$ahead}s ahead refused.";
    }

    private function checkIssuedInFuture(): string
    {
        $ahead = $this->validator()->leeway + 30;

        $this->assertRejected(
            $this->forge()->sign($this->forge()->payload([
                'iat' => time() + $ahead,
                'exp' => time() + $ahead + 900,
            ], remove: ['nbf'])),
            'token_not_yet_valid',
        );

        return "A token with `iat` {$ahead}s ahead refused.";
    }

    private function checkLeewayCapped(): string
    {
        $configured = (int) $this->config->get('wollerp-auth.token.leeway', TokenValidator::DEFAULT_LEEWAY);
        $effective = $this->validator()->leeway;

        if ($effective > TokenValidator::MAX_LEEWAY) {
            throw new CheckFailed(sprintf(
                'Effective leeway is %ds, above the contract maximum of %ds. Every revoked and '
                .'expired token in the estate lives %ds longer than it should.',
                $effective,
                TokenValidator::MAX_LEEWAY,
                $effective - TokenValidator::MAX_LEEWAY,
            ));
        }

        if ($effective < 0) {
            throw new CheckFailed("Effective leeway is negative ({$effective}s).");
        }

        return $configured > $effective
            ? "Configured {$configured}s, clamped to {$effective}s."
            : "{$effective}s, within the {$configured}s configured and the ".TokenValidator::MAX_LEEWAY.'s cap.';
    }

    // ── Structure and required claims ────────────────────────────────────────

    private function checkRequiredClaimsAbsent(): string
    {
        $required = ['exp', 'sub', 'uid', 'jti', 'sid', 'ver'];

        foreach ($required as $claim) {
            $this->assertRejected(
                $this->forge()->sign($this->forge()->payload(remove: [$claim])),
                'token_claims_invalid',
                sprintf('missing `%s`', $claim),
            );
        }

        return implode(', ', $required).' each required.';
    }

    private function checkMalformedTokens(): string
    {
        $malformed = [
            '',
            'not-a-token',
            'aGVhZGVy.cGF5bG9hZA',
            'a.b.c.d',
            '..',
            'héader.payload.signature',
        ];

        foreach ($malformed as $token) {
            $this->assertRejectedWithAny(
                $token,
                ['token_malformed', 'token_missing'],
                sprintf('"%s"', $token === '' ? '(empty)' : $token),
            );
        }

        return count($malformed).' malformed inputs refused.';
    }

    private function checkOversizedToken(): string
    {
        $limit = (int) $this->config->get('wollerp-auth.token.max_length', 8192);

        $this->assertRejected(str_repeat('A', $limit + 1).'.b.c', 'token_malformed');

        return "Refused above the configured {$limit} byte limit, before any crypto.";
    }

    // ── Happy path ───────────────────────────────────────────────────────────

    private function checkValidTokenAccepted(): string
    {
        $payload = $this->forge()->payload();
        $claims = $this->assertAccepted($this->forge()->sign($payload));

        foreach (['sub', 'jti', 'sid'] as $claim) {
            if ($claims->get($claim) !== $payload[$claim]) {
                throw new CheckFailed("Accepted, but `{$claim}` did not survive validation intact.");
            }
        }

        if ($claims->uid() !== $payload['uid']) {
            throw new CheckFailed('Accepted, but `uid` did not survive validation intact.');
        }

        return sprintf(
            'Accepted for iss=%s aud=%s; identity, revocation and version claims intact.',
            $claims->iss(),
            implode(',', $claims->aud()),
        );
    }

    private function checkAudienceStringNormalised(): string
    {
        $claims = $this->assertAccepted(
            $this->forge()->sign($this->forge()->payload(['aud' => $this->forge()->audience])),
        );

        if ($claims->aud() !== [$this->forge()->audience]) {
            throw new CheckFailed('A bare-string `aud` was not normalised to a single-element array.');
        }

        return 'A bare-string `aud` normalised to an array.';
    }

    private function checkNoAuthorisationClaims(): string
    {
        $claims = $this->assertAccepted($this->forge()->sign($this->forge()->payload()));

        foreach (self::FORBIDDEN_CLAIMS as $forbidden) {
            if ($claims->has($forbidden)) {
                throw new CheckFailed(sprintf(
                    'The validated token exposes `%s`. CONTRACT §1 keeps authorisation out of the '
                    .'token: a claim like this is a stale authority cache with a 15 minute lifetime, '
                    .'so a revoked role stays live until the token expires.',
                    $forbidden,
                ));
            }
        }

        return count(self::FORBIDDEN_CLAIMS).' authorisation claims confirmed absent.';
    }

    // ── Wiring ───────────────────────────────────────────────────────────────

    private function checkAudienceConfigured(): string
    {
        $audience = $this->config->get('wollerp-auth.audience');

        if (! is_string($audience) || trim($audience) === '') {
            throw new CheckFailed(
                'wollerp-auth.audience is empty. Set WOLLERP_SERVICE_SLUG to this product\'s '
                .'registry slug (CONTRACT §7). The package ships no default on purpose: a baked-in '
                .'one would mean a mis-deployed backend announces itself as somebody else and '
                .'accepts that product\'s tokens.'
            );
        }

        if ($audience !== trim($audience)) {
            throw new CheckFailed(sprintf(
                'wollerp-auth.audience is "%s" — it has leading or trailing whitespace, and the '
                .'audience comparison is exact, so no token will ever match it.',
                $audience,
            ));
        }

        return "Audience is \"{$audience}\".";
    }

    private function checkIssuerConfigured(): string
    {
        $issuer = $this->config->get('wollerp-auth.issuer');

        if (! is_string($issuer) || trim($issuer) === '') {
            throw new CheckFailed('wollerp-auth.issuer is empty. Set WOLLERP_AUTH_ISSUER.');
        }

        if ($issuer !== trim($issuer)) {
            throw new CheckFailed(sprintf(
                'wollerp-auth.issuer is "%s" — the whitespace makes the exact-match check '
                .'unsatisfiable.',
                $issuer,
            ));
        }

        return "Issuer is \"{$issuer}\".";
    }

    private function checkGuardDriverResolves(): string
    {
        if ($this->auth === null) {
            throw new CheckSkipped('No auth factory available in this context.');
        }

        $name = (string) $this->config->get('wollerp-auth.guard', 'wollerp');

        try {
            $guard = $this->auth->guard($name);
        } catch (Throwable $error) {
            throw new CheckFailed(sprintf(
                'Guard [%s] could not be resolved (%s). Add "%s" => ["driver" => "wollerp"] to '
                .'config/auth.php.',
                $name,
                $error->getMessage(),
                $name,
            ));
        }

        if (! $guard instanceof TokenGuard) {
            throw new CheckFailed(sprintf(
                'Guard [%s] resolved to %s, not a Wollerp TokenGuard. Routes using auth:%s are not '
                .'validating Wollerp tokens.',
                $name,
                $guard::class,
                $name,
            ));
        }

        return "auth:{$name} resolves to the Wollerp TokenGuard.";
    }

    private function checkMiddlewareAliases(): string
    {
        if ($this->router === null) {
            throw new CheckSkipped('No router bound in this context.');
        }

        $aliases = $this->router->getMiddleware();

        $expected = [
            'wollerp.auth' => Authenticate::class,
            'wollerp.hmac' => VerifyHmacSignature::class,
        ];

        foreach ($expected as $alias => $class) {
            if (! isset($aliases[$alias])) {
                throw new CheckFailed("Middleware alias [{$alias}] is not registered.");
            }

            if ($aliases[$alias] !== $class) {
                throw new CheckFailed(sprintf(
                    'Middleware alias [%s] resolves to %s, not %s — a product-defined alias is '
                    .'shadowing the package\'s.',
                    $alias,
                    is_string($aliases[$alias]) ? $aliases[$alias] : gettype($aliases[$alias]),
                    $class,
                ));
            }
        }

        return 'wollerp.auth and wollerp.hmac both registered.';
    }

    private function checkRevocationBites(): string
    {
        if ($this->denylist === null || $this->denylistConnection === null) {
            throw new CheckSkipped('No denylist factory supplied to the suite.');
        }

        $denylist = ($this->denylist)();
        $connection = ($this->denylistConnection)();

        // `sid` is CHAR(26). Stay inside it, and stay unmistakably synthetic.
        $sid = '01CONFORMANCEPROBE'.bin2hex(random_bytes(4));

        $connection->beginTransaction();

        try {
            if ($denylist->matches($sid, null)) {
                throw new CheckFailed(
                    'The denylist matched a random sid that was never revoked. The predicate is '
                    .'matching everything, which means nothing is ever authenticated.'
                );
            }

            $denylist->revoke($sid, null, time() + 900, 'conformance');

            if (! $denylist->matches($sid, null)) {
                throw new CheckFailed(
                    'A revoked sid was NOT matched. CONTRACT §2 layer 2 is not biting: logout, '
                    .'reuse detection and admin revocation all do nothing, and every issued token '
                    .'stays live for its full TTL no matter what the auth server says.'
                );
            }
        } finally {
            $connection->rollBack();
        }

        if ($denylist->matches($sid, null)) {
            throw new CheckFailed(
                'The probe row survived a transaction rollback, so this check has written to the '
                .'denylist. Remove the row for sid '.$sid.'.'
            );
        }

        return 'A revoked sid was matched and the probe row rolled back cleanly.';
    }

    private function checkMirrorHasNoCredentialColumns(): string
    {
        $model = $this->mirrorModelOrSkip();

        $columns = array_map(
            strtolower(...),
            $model->getConnection()->getSchemaBuilder()->getColumnListing($model->getTable()),
        );

        if ($columns === []) {
            throw new CheckFailed(sprintf(
                'Table [%s] on connection [%s] has no columns, or does not exist. Run the published '
                .'migrations.',
                $model->getTable(),
                $model->getConnectionName() ?? 'default',
            ));
        }

        foreach (['password', 'remember_token', 'password_hash'] as $forbidden) {
            if (in_array($forbidden, $columns, true)) {
                throw new CheckFailed(sprintf(
                    'The mirror table [%s] has a `%s` column. CONTRACT §4: the product database must '
                    .'never be capable of authenticating anyone.',
                    $model->getTable(),
                    $forbidden,
                ));
            }
        }

        return sprintf('[%s] has %d columns and no credential surface.', $model->getTable(), count($columns));
    }

    private function checkMirrorWriteGuard(): string
    {
        $model = $this->mirrorModelOrSkip();

        $connection = $model->getConnection();
        $connection->beginTransaction();

        try {
            $probe = $model->newInstance([
                'auth_user_id' => 999000002,
                'auth_user_uuid' => '01CONFORMANCEWRITE00000000',
                'name' => 'Conformance Probe',
            ]);

            try {
                $probe->save();
            } catch (MirrorWriteForbiddenException) {
                return 'A direct save() on the mirror model throws, as CONTRACT §4 requires.';
            }

            throw new CheckFailed(sprintf(
                'A direct save() on %s succeeded. The mirror is writable by product code, so it can '
                .'drift from the auth server with nothing to detect it.',
                $model::class,
            ));
        } finally {
            $connection->rollBack();
        }
    }

    private function checkBundledKeysUsable(): string
    {
        $bundled = $this->bundledKeys();

        if ($bundled === []) {
            throw new CheckSkipped('No bundled keys configured; see posture.jwks.bundled_keys_present.');
        }

        // Round-trip them through the same conversion the hot path uses, rather
        // than eyeballing the shape: RSA only, RS256 only, use=sig, >= 2048
        // bits, and it has to parse.
        $client = new JwksClient(
            $this->offlineHttp(),
            $this->isolatedJwksCache(),
            'https://wollerp-conformance.invalid/.well-known/jwks.json',
            $bundled,
        );

        $usable = 0;
        $rejected = [];

        foreach ($bundled as $index => $jwk) {
            $kid = is_array($jwk) && isset($jwk['kid']) && is_string($jwk['kid']) ? $jwk['kid'] : null;

            if ($kid === null || $kid === '') {
                $rejected[] = "entry #{$index} has no `kid`";

                continue;
            }

            try {
                $client->publicKeyFor($kid);
                $usable++;
            } catch (Throwable) {
                $rejected[] = sprintf('kid "%s" did not convert to a usable RS256 key', $kid);
            }
        }

        if ($rejected !== []) {
            throw new CheckFailed(sprintf(
                '%d of %d bundled keys are unusable (%s). A bundle that looks configured and is not '
                .'is worse than an empty one: the cold-start fallback will not fire when it is needed.',
                count($rejected),
                count($bundled),
                implode('; ', $rejected),
            ));
        }

        return "{$usable} bundled key(s) convert to usable RS256 keys.";
    }

    // ── Posture ──────────────────────────────────────────────────────────────

    private function checkBundledKeysPresent(): string
    {
        $bundled = $this->bundledKeys();

        if ($bundled === []) {
            throw new CheckFailed(
                'jwks.bundled_keys is empty. If the JWKS endpoint is unreachable while this host\'s '
                .'cache is cold — a deploy, a scale-out, a cache flush during an Auth incident — '
                .'every request returns 503 until the endpoint comes back. Populate it from '
                .'WOLLERP_AUTH_BUNDLED_JWKS at deploy time; see INTEGRATION.md.'
            );
        }

        return count($bundled).' bundled key(s) configured for a cold-start JWKS outage.';
    }

    private function checkJwksUrlMatchesIssuer(): string
    {
        $issuer = (string) $this->config->get('wollerp-auth.issuer', '');
        $url = (string) $this->config->get('wollerp-auth.jwks.url', '');

        if ($url === '') {
            throw new CheckFailed('jwks.url is empty; no key material can ever be fetched.');
        }

        $issuerHost = parse_url($issuer, PHP_URL_HOST);
        $jwksHost = parse_url($url, PHP_URL_HOST);

        if (! is_string($jwksHost) || $jwksHost === '') {
            throw new CheckFailed("jwks.url \"{$url}\" has no host.");
        }

        if ($issuerHost !== $jwksHost) {
            throw new CheckFailed(sprintf(
                'The JWKS host (%s) is not the issuer host (%s). Identity and key material are '
                .'coming from different places — usually a stale WOLLERP_AUTH_JWKS_URL left over '
                .'from another environment.',
                $jwksHost,
                is_string($issuerHost) ? $issuerHost : '(none)',
            ));
        }

        return "JWKS served from the issuer origin ({$jwksHost}).";
    }

    private function checkServicePlaneControls(): string
    {
        $secrets = $this->config->get('wollerp-auth.hmac.secrets', []);
        $secrets = is_array($secrets) ? array_filter($secrets, static fn (mixed $v): bool => is_string($v) && $v !== '') : [];

        if ($secrets === []) {
            throw new CheckFailed(
                'No inbound HMAC secret is configured (WOLLERP_HMAC_SECRET_AUTH). The '
                .'/internal/revoke webhook cannot be verified, so CONTRACT §2 layer 2 is fed by '
                .'nothing: logout stops propagating and a revoked session stays live for its full TTL.'
            );
        }

        $allowedIps = $this->config->get('wollerp-auth.hmac.allowed_ips', []);
        $allowedIps = is_array($allowedIps) ? $allowedIps : [];

        return sprintf(
            '%d inbound secret(s) configured; IP allowlist %s.',
            count($secrets),
            $allowedIps === []
                ? 'empty (CONTRACT §5 expects it enforced here or upstream at the load balancer)'
                : 'has '.count($allowedIps).' entr'.(count($allowedIps) === 1 ? 'y' : 'ies'),
        );
    }

    // ── Assertion helpers ────────────────────────────────────────────────────

    /**
     * Deliberately loud. Every use of this guards a bypass.
     */
    private function assertRejected(string $token, string $expectedReason, string $context = ''): void
    {
        $this->assertRejectedWithAny($token, [$expectedReason], $context);
    }

    /**
     * @param  list<string>  $acceptableReasons
     */
    private function assertRejectedWithAny(string $token, array $acceptableReasons, string $context = ''): void
    {
        $suffix = $context === '' ? '' : " ({$context})";

        try {
            $this->validator()->validate($token);
        } catch (WollerpAuthException $exception) {
            if (! in_array($exception->reason(), $acceptableReasons, true)) {
                throw new CheckFailed(sprintf(
                    'Rejected%s, but for the wrong reason: expected %s, got `%s`. The token did not '
                    .'get through, but the check that stopped it is not the one being verified.',
                    $suffix,
                    implode(' or ', array_map(static fn (string $r): string => "`{$r}`", $acceptableReasons)),
                    $exception->reason(),
                ));
            }

            return;
        }

        throw new CheckFailed(
            "The token was ACCEPTED{$suffix}. This is an authentication bypass."
        );
    }

    private function assertAccepted(string $token): Claims
    {
        try {
            return $this->validator()->validate($token);
        } catch (WollerpAuthException $exception) {
            throw new CheckFailed(sprintf(
                'A token this validator should accept was refused as `%s`: %s',
                $exception->reason(),
                $exception->getMessage(),
            ));
        }
    }

    // ── Isolated validator ───────────────────────────────────────────────────

    /**
     * A TokenValidator built from the consumer's REAL issuer, audience, leeway
     * and length limit, resolving keys from an ephemeral in-process keypair.
     *
     * The container's own TokenValidator is deliberately not used: it resolves
     * keys from the live JWKS, and we hold no production private key to mint
     * test tokens with. The class, the pinning and the configured values are
     * the consumer's; only the key material is ours.
     */
    private function validator(): TokenValidator
    {
        if ($this->validator !== null) {
            return $this->validator;
        }

        $jwks = new JwksClient(
            $this->offlineHttp(),
            $this->isolatedJwksCache(),
            'https://wollerp-conformance.invalid/.well-known/jwks.json',
            // Handed in as the bundled set so the real JWK → PEM conversion,
            // the RS256 filter and the 2048-bit floor are all exercised in the
            // consumer's own OpenSSL build.
            [$this->forge()->jwk()],
        );

        return $this->validator = new TokenValidator(
            $jwks,
            (string) $this->config->get('wollerp-auth.issuer', ''),
            (string) $this->config->get('wollerp-auth.audience', ''),
            (int) $this->config->get('wollerp-auth.token.leeway', TokenValidator::DEFAULT_LEEWAY),
            (int) $this->config->get('wollerp-auth.token.max_length', 8192),
        );
    }

    private function forge(): TokenForge
    {
        return $this->forge ??= new TokenForge(
            (string) $this->config->get('wollerp-auth.issuer', ''),
            (string) $this->config->get('wollerp-auth.audience', ''),
        );
    }

    /**
     * An HTTP factory that cannot reach anything. The conformance run must not
     * touch the network — not the auth server, not the JWKS endpoint, nothing —
     * so that it is safe to run on a production host and deterministic in CI
     * with no egress.
     */
    private function offlineHttp(): HttpFactory
    {
        $http = new HttpFactory;

        $http->preventStrayRequests();
        $http->fake(static fn (): mixed => HttpFactory::response(
            'wollerp:conformance makes no network calls',
            503,
        ));

        return $http;
    }

    /**
     * A private in-memory cache. Never the consumer's real JWKS cache: writing
     * an ephemeral public key into it under any kid would be a genuine security
     * incident, and evicting the real one would cause a fetch storm.
     */
    private function isolatedJwksCache(): JwksCache
    {
        return new JwksCache(
            new CacheRepository(new ArrayStore),
            'wollerp-auth:conformance:'.bin2hex(random_bytes(8)),
            21600,
            0,
        );
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function bundledKeys(): array
    {
        $bundled = $this->config->get('wollerp-auth.jwks.bundled_keys', []);

        if (! is_array($bundled)) {
            return [];
        }

        return array_values(array_filter($bundled, is_array(...)));
    }

    private function mirrorModelOrSkip(): Model
    {
        if ($this->mirrorModel === null) {
            throw new CheckSkipped('No mirror model factory supplied to the suite.');
        }

        if ($this->config->get('wollerp-auth.mirror.enabled', true) === false) {
            throw new CheckSkipped('The user mirror is disabled in this product.');
        }

        $model = ($this->mirrorModel)();

        if (! $model instanceof Model) {
            throw new CheckFailed(sprintf(
                'wollerp-auth.mirror.model resolved to %s, which is not an Eloquent model.',
                get_debug_type($model),
            ));
        }

        return $model;
    }
}
