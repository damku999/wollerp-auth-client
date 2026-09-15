<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Wollerp\AuthClient\Tests\Support\TokenFactory;

/**
 * LAYER 2, CONTRACT §2 step 8 and §6.
 *
 * Layer 1 passes here in every case — these are genuine, unexpired, correctly
 * audienced tokens signed with the real key. The denylist is the only thing
 * standing between a logged-out or compromised session and a live request, for
 * the remainder of the 15 minute access-token TTL.
 *
 * `sid` kills a whole refresh-token family (logout everywhere, reuse detection,
 * admin session revocation). `jti` kills one access token.
 */
beforeEach(function (): void {
    $this->token = $this->tokens->sign($this->tokens->payload());
});

it('rejects a token whose sid is on the denylist', function (): void {
    $this->denylist()->revoke(TokenFactory::SID, null, time() + 900);

    $exception = rejects(
        fn () => $this->guard()->authenticateRequest($this->requestWithToken($this->token))
    );

    expect($exception->reason())->toBe('token_revoked')
        ->and($exception->status())->toBe(401);
});

it('rejects a token whose jti is on the denylist', function (): void {
    $this->denylist()->revoke(null, TokenFactory::JTI, time() + 900);

    expect(rejects(
        fn () => $this->guard()->authenticateRequest($this->requestWithToken($this->token))
    )->reason())->toBe('token_revoked');
});

it('accepts the same token before the revocation row exists', function (): void {
    $claims = $this->guard()->authenticateRequest($this->requestWithToken($this->token));

    expect($claims->sid())->toBe(TokenFactory::SID);
});

it('does not revoke an unrelated session', function (): void {
    $this->denylist()->revoke('01OTHERSESSION00000000000A', null, time() + 900);

    $claims = $this->guard()->authenticateRequest($this->requestWithToken($this->token));

    expect($claims->uid())->toBe(TokenFactory::UID);
});

it('checks the denylist with a single query', function (): void {
    $claims = $this->validator()->validate($this->token);

    DB::enableQueryLog();
    $this->denylist()->isRevoked($claims);
    $queries = DB::getQueryLog();
    DB::disableQueryLog();

    expect($queries)->toHaveCount(1);
});

it('prunes rows whose expires_at has passed', function (): void {
    $this->denylist()->revoke(TokenFactory::SID, null, time() - 60);

    expect($this->denylist()->matches(TokenFactory::SID, null))->toBeTrue();

    $removed = $this->denylist()->prune();

    expect($removed)->toBe(1)
        ->and($this->denylist()->matches(TokenFactory::SID, null))->toBeFalse();
});
