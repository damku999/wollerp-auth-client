<?php

declare(strict_types=1);

use Wollerp\AuthClient\Tests\Support\TokenFactory;

/**
 * CONTRACT §2 step 4. Nothing subtle here — it just has to actually happen.
 */
it('rejects a token whose signature has been altered by one byte', function (): void {
    $token = $this->tokens->tamperSignature(
        $this->tokens->sign($this->tokens->payload())
    );

    $exception = rejects(fn () => $this->validator()->validate($token));

    expect($exception->reason())->toBe('token_signature_invalid')
        ->and($exception->status())->toBe(401);
});

it('rejects a token whose payload was swapped under a valid signature', function (): void {
    $original = $this->tokens->sign($this->tokens->payload());

    $escalated = $this->tokens->tamperPayload($original, $this->tokens->payload([
        'uid' => 1,
        'sub' => '01JADMIN0000000000000000AA',
    ]));

    expect(rejects(fn () => $this->validator()->validate($escalated))->reason())
        ->toBe('token_signature_invalid');
});

it('rejects a token signed by a key that is not the published one', function (): void {
    $impostor = new TokenFactory($this->tokens->kid);

    // Same `kid` as the real key, different private key behind it.
    $token = $impostor->sign($impostor->payload());

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_signature_invalid');
});

it('rejects structurally broken tokens', function (string $token): void {
    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBeIn(['token_malformed', 'token_missing']);
})->with([
    'empty' => '',
    'one segment' => 'not-a-token',
    'two segments' => 'aGVhZGVy.cGF5bG9hZA',
    'four segments' => 'a.b.c.d',
    'dots only' => '..',
    'not base64url' => 'héader.payload.signature',
]);

it('rejects an absurdly long token before doing any crypto', function (): void {
    $token = str_repeat('A', 9000).'.b.c';

    expect(rejects(fn () => $this->validator()->validate($token))->reason())
        ->toBe('token_malformed');
});
