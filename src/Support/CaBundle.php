<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Support;

/**
 * Where the client is willing to be told which CA to trust — and nowhere is it
 * willing to be told not to check.
 *
 * Every outbound hop to the auth server is TLS-verified. A product can NAME a
 * certificate authority (a private CA, or the self-signed certificate a local
 * `.test` vhost presents), and that is the whole of the configuration surface:
 * there is deliberately no `verify => false`, no `WOLLERP_AUTH_INSECURE`, and no
 * environment in which one is honoured. A switch that turns verification off is
 * used once in development and then found, years later, still set in production
 * — and a service plane that does not verify its peer is a service plane that
 * can be answered by anyone on the path.
 *
 * ── Why this class exists rather than three copies of two lines ──────────────
 * It did exist as two lines, in one place: Coms Coupler's own ServicePlaneClient
 * applied a bundle on its outbound POSTs. Nothing else did. So `users:sync`
 * (a GET, in this package) and the JWKS fetch both ignored the setting
 * entirely, and the product's `WOLLERP_AUTH_CA_BUNDLE` looked configured while
 * covering roughly a third of the traffic. `users:sync` failed with cURL 60
 * against a local vhost whose certificate the product had already been told to
 * trust.
 */
final class CaBundle
{
    /**
     * Guzzle options naming the CA to verify against, or none.
     *
     * An unreadable path yields no option rather than an error: the request
     * then verifies against the system trust store, which is the correct
     * default and fails loudly at the TLS layer if the peer is not trusted. A
     * typo in a path must not be a way to end up trusting less than the
     * default.
     *
     * @return array{verify?: string}
     */
    public static function options(string $path): array
    {
        $path = trim($path);

        if ($path === '' || ! is_readable($path)) {
            return [];
        }

        return ['verify' => $path];
    }
}
