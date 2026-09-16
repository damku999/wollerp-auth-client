<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Conformance;

use RuntimeException;

/**
 * Internal control flow for ConformanceSuite: a check raises this to report
 * that it did not hold. Never escapes the suite — run() converts it into a
 * CheckResult.
 */
final class CheckFailed extends RuntimeException {}
