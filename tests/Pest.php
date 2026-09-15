<?php

declare(strict_types=1);

use PHPUnit\Framework\Assert;
use Wollerp\AuthClient\Exceptions\WollerpAuthException;
use Wollerp\AuthClient\Tests\TestCase;

uses(TestCase::class)->in('Conformance', 'Feature');

/**
 * Asserts that a validation call rejected, and hands back the exception so the
 * test can assert on the reason.
 *
 * The failure message is deliberately loud: every use of this helper in the
 * conformance suite guards a complete authentication bypass.
 */
function rejects(Closure $callback): WollerpAuthException
{
    try {
        $callback();
    } catch (WollerpAuthException $exception) {
        return $exception;
    }

    Assert::fail('The token was ACCEPTED. This is an authentication bypass.');
}
