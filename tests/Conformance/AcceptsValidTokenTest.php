<?php

declare(strict_types=1);

use Wollerp\AuthClient\Tests\Support\TokenFactory;

it('accepts a well-formed RS256 token and exposes every contract claim', function (): void {
    $claims = $this->validator()->validate(
        $this->tokens->sign($this->tokens->payload())
    );

    expect($claims->sub())->toBe(TokenFactory::SUB)
        ->and($claims->uid())->toBe(TokenFactory::UID)
        ->and($claims->aud())->toBe(['cc'])
        ->and($claims->iss())->toBe(TokenFactory::ISSUER)
        ->and($claims->jti())->toBe(TokenFactory::JTI)
        ->and($claims->sid())->toBe(TokenFactory::SID)
        ->and($claims->ver())->toBe(7)
        ->and($claims->email())->toBe('user@example.com')
        ->and($claims->name())->toBe('Jane Smith')
        ->and($claims->emailVerified())->toBeTrue()
        ->and($claims->amr())->toBe(['pwd', 'otp'])
        ->and($claims->authTime())->toBeInt();
});

it('returns aud as an array even when the issuer sends a bare string', function (): void {
    $claims = $this->validator()->validate(
        $this->tokens->sign($this->tokens->payload(['aud' => 'cc']))
    );

    expect($claims->aud())->toBe(['cc']);
});

it('accepts a token whose aud lists several products including this one', function (): void {
    $claims = $this->validator()->validate(
        $this->tokens->sign($this->tokens->payload(['aud' => ['bc', 'cc', 'we']]))
    );

    expect($claims->aud())->toContain('cc');
});

it('answers the re-auth question from auth_time without calling the auth server', function (): void {
    $claims = $this->validator()->validate(
        $this->tokens->sign($this->tokens->payload(['auth_time' => time() - 120]))
    );

    expect($claims->authenticatedWithin(300))->toBeTrue()
        ->and($claims->authenticatedWithin(60))->toBeFalse();
});

it('fails the re-auth check closed when the issuer omitted auth_time', function (): void {
    $claims = $this->validator()->validate(
        $this->tokens->sign($this->tokens->payload(remove: ['auth_time']))
    );

    expect($claims->authTime())->toBeNull()
        ->and($claims->authenticatedWithin(86400))->toBeFalse();
});

it('carries no authorisation claims — CONTRACT §1 "absent by design"', function (): void {
    $claims = $this->validator()->validate(
        $this->tokens->sign($this->tokens->payload())
    );

    foreach ([
        'roles', 'permissions', 'subscription', 'plan', 'modules',
        'active_profile_type', 'company_id', 'client_id', 'professional_id',
    ] as $forbidden) {
        expect($claims->has($forbidden))->toBeFalse(
            "A token carrying `{$forbidden}` is a stale authority cache with a 15 minute lifetime."
        );
    }
});

it('authenticates a request end to end through the wollerp guard', function (): void {
    $request = $this->requestWithToken($this->tokens->sign($this->tokens->payload()));

    $claims = $this->guard()->authenticateRequest($request);

    expect($claims->uid())->toBe(TokenFactory::UID)
        ->and($this->guard()->check())->toBeTrue();
});
