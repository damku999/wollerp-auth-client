<?php

declare(strict_types=1);

use Wollerp\AuthClient\Token\TokenValidator;

/**
 * CONTRACT §2 step 7 and §7. This service is `cc`. A token minted for Brick
 * Case must not open a Coms Coupler session — otherwise any product that gets
 * compromised, or any product a user has a legitimate account on, becomes a
 * lateral path into every other product in the estate.
 *
 * Signed with the real key in every case; only the audience check applies.
 */
it('rejects a token audienced to another product', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(['aud' => ['bc']]));

    $exception = rejects(fn () => $this->validator()->validate($token));

    expect($exception->reason())->toBe('token_audience_mismatch')
        ->and($exception->status())->toBe(401);
});

it('rejects an audience array that excludes this service', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(['aud' => ['bc', 'we']]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_audience_mismatch');
});

it('rejects an empty audience array', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(['aud' => []]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_audience_mismatch');
});

it('rejects audience values that only look like this service', function (string $audience): void {
    $token = $this->tokens->sign($this->tokens->payload(['aud' => [$audience]]));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_audience_mismatch');
})->with(['CC', 'cc ', ' cc', 'ccc', 'cc,bc', 'c']);

it('rejects a token with no aud claim', function (): void {
    $token = $this->tokens->sign($this->tokens->payload(remove: ['aud']));

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_claims_invalid');
});

/**
 * CONTRACT §7 makes the product registry OPEN, so this package cannot ship a
 * default slug — and an unset one must be an error, not an empty comparison.
 * A backend that does not know which product it is cannot decide whose tokens
 * it accepts.
 */
it('refuses to construct a validator with no audience configured', function (?string $audience): void {
    config()->set('wollerp-auth.audience', $audience);
    $this->app->forgetInstance(TokenValidator::class);

    expect(fn () => $this->validator())->toThrow(InvalidArgumentException::class);
})->with(['unset' => null, 'empty' => '']);

it('refuses to construct a validator with no issuer configured', function (): void {
    config()->set('wollerp-auth.issuer', null);
    $this->app->forgetInstance(TokenValidator::class);

    expect(fn () => $this->validator())->toThrow(InvalidArgumentException::class);
});
