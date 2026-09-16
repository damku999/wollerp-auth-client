<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Support;

use Illuminate\Contracts\Config\Repository as ConfigRepository;

/**
 * Undoes Laravel's deep merge of its OWN `config/auth.php` defaults, but only
 * where the merged-in entry cannot possibly work.
 *
 * ── The problem ──────────────────────────────────────────────────────────────
 * Since Laravel 11 the framework RECURSIVELY merges its shipped default for
 * every config file the application also defines. Deleting `App\Models\User`
 * and reducing `config/auth.php` to nothing but the `wollerp` guard therefore
 * does NOT remove the rest of it. `config('auth')` still resolves to:
 *
 *     guards.web        session driver, provider `users`
 *     providers.users   eloquent, model App\Models\User      ← deleted class
 *     passwords.users   table `password_reset_tokens`        ← no such table
 *     defaults.passwords  'users'                            ← that broker
 *
 * None of it is reachable without a session driver, so it is not a live bypass.
 * It is worse in a quieter way: a product whose entire premise is "this database
 * cannot authenticate anyone" (CONTRACT §4) ships with a password-reset broker
 * and a session guard configured and one `Auth::guard('web')` away from a
 * confusing runtime error — **and a reviewer reading `config/auth.php` sees none
 * of it, because none of it is in the file.** The only way to see it is to dump
 * `config('auth')` on a booted application, which nobody does during review.
 *
 * A config file cannot delete a key the merge adds, so this has to be code, and
 * it has to run in `register()`: after configuration is loaded, before anything
 * resolves the auth manager. That is the only safe window.
 *
 * ── What it removes, exactly ─────────────────────────────────────────────────
 * Three passes, in order, and nothing else is touched:
 *
 *   1. `auth.providers.*` where `driver` is `eloquent` and `model` names a class
 *      that does not exist. An eloquent provider pointing at a missing class can
 *      only ever throw; there is no configuration in which it works.
 *   2. `auth.guards.*` and `auth.passwords.*` whose `provider` key names a
 *      provider removed by pass 1. Same argument — the reference now dangles.
 *   3. `auth.defaults.passwords`, if it names a broker removed by pass 2.
 *
 * ── What it deliberately does NOT do ─────────────────────────────────────────
 * - It never removes anything the product could plausibly mean. A product that
 *   wants a session guard has a User model, pass 1 finds nothing, and the whole
 *   routine is a no-op. Coms Coupler — which keeps `web`, `api` (Passport) and
 *   `providers.users` on purpose through its soak period, because dual-accept is
 *   its rollback — is unaffected.
 * - It never touches a guard with no `provider` key, which is what the `wollerp`
 *   guard is.
 * - It never touches `auth.defaults.guard`. Repointing the default guard is a
 *   decision about how the application behaves, not a consistency repair, and it
 *   is the product's to make.
 * - It never touches a `database`-driver provider: verifying that one would mean
 *   querying the database from `register()`.
 *
 * Because the removals are invisible in `config/auth.php` by construction, what
 * was removed is recorded at `wollerp-auth.runtime.pruned_auth_config` so it can
 * be read back on a live host:
 *
 *     php artisan tinker --execute="dd(config('wollerp-auth.runtime'));"
 *
 * Set `WOLLERP_AUTH_HARDEN_AUTH_CONFIG=false` to switch the whole thing off.
 */
final class AuthConfigHardener
{
    public const RECORD_KEY = 'wollerp-auth.runtime.pruned_auth_config';

    /**
     * @return list<string> the dot-notation `auth.*` keys removed, in the order
     *                      they were removed. Empty on a healthy configuration.
     */
    public static function prune(ConfigRepository $config): array
    {
        $removed = [];

        $providers = self::section($config, 'auth.providers');
        $survivingProviders = $providers;

        foreach ($providers as $name => $definition) {
            if (! self::isUnusableEloquentProvider($definition)) {
                continue;
            }

            unset($survivingProviders[$name]);
            $removed[] = "auth.providers.{$name}";
        }

        if ($removed === []) {
            self::record($config, []);

            return [];
        }

        $config->set('auth.providers', $survivingProviders);

        foreach (['guards', 'passwords'] as $section) {
            $entries = self::section($config, "auth.{$section}");
            $surviving = $entries;

            foreach ($entries as $name => $definition) {
                if (! self::referencesMissingProvider($definition, $survivingProviders)) {
                    continue;
                }

                unset($surviving[$name]);
                $removed[] = "auth.{$section}.{$name}";
            }

            if ($surviving !== $entries) {
                $config->set("auth.{$section}", $surviving);
            }
        }

        $defaultBroker = $config->get('auth.defaults.passwords');

        if (is_string($defaultBroker) && ! array_key_exists($defaultBroker, self::section($config, 'auth.passwords'))) {
            $defaults = self::section($config, 'auth.defaults');
            unset($defaults['passwords']);

            $config->set('auth.defaults', $defaults);
            $removed[] = 'auth.defaults.passwords';
        }

        self::record($config, $removed);

        return $removed;
    }

    /**
     * @param  mixed  $definition
     */
    private static function isUnusableEloquentProvider($definition): bool
    {
        if (! is_array($definition)) {
            return false;
        }

        if (($definition['driver'] ?? null) !== 'eloquent') {
            return false;
        }

        $model = $definition['model'] ?? null;

        // A non-string `model` is as broken as a missing class, and an empty
        // string resolves to nothing. Both can only throw at first use.
        return ! is_string($model) || $model === '' || ! class_exists($model);
    }

    /**
     * @param  mixed  $definition
     * @param  array<string, mixed>  $survivingProviders
     */
    private static function referencesMissingProvider($definition, array $survivingProviders): bool
    {
        if (! is_array($definition)) {
            return false;
        }

        $provider = $definition['provider'] ?? null;

        // No `provider` key at all is the `wollerp` guard's shape: it resolves
        // the caller from the mirror itself. Nothing to dangle, nothing to do.
        if (! is_string($provider) || $provider === '') {
            return false;
        }

        return ! array_key_exists($provider, $survivingProviders);
    }

    /**
     * @return array<string, mixed>
     */
    private static function section(ConfigRepository $config, string $key): array
    {
        $value = $config->get($key, []);

        return is_array($value) ? $value : [];
    }

    /**
     * @param  list<string>  $removed
     */
    private static function record(ConfigRepository $config, array $removed): void
    {
        $config->set(self::RECORD_KEY, $removed);
    }
}
