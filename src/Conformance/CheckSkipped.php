<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Conformance;

use RuntimeException;

/**
 * Internal control flow for ConformanceSuite: a check raises this when it
 * cannot run in this environment at all — no database connection to probe, no
 * router bound outside an HTTP kernel.
 *
 * Only WIRING and POSTURE checks may skip. A PIN check has no environmental
 * prerequisite beyond OpenSSL, so it always runs and always counts.
 */
final class CheckSkipped extends RuntimeException {}
