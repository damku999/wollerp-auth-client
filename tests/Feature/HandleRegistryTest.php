<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Wollerp\AuthClient\Exceptions\HandleRegistryException;
use Wollerp\AuthClient\Handles\HandleRegistryClient;
use Wollerp\AuthClient\Hmac\Signer;
use Wollerp\AuthClient\Mirror\MirrorSynchroniser;
use Wollerp\AuthClient\Tests\Support\TokenFactory;

/**
 * CONTRACT §5.6 from the product side: the four signed calls, the HDL_* refusals
 * mapped to reasons, "Auth unreachable" kept distinct from "Auth said no", and
 * `handle` carried into users_mirror.
 */
function handles(): HandleRegistryClient
{
    return app(HandleRegistryClient::class);
}

function envelope(array $data, int $status = 200): mixed
{
    return Http::response([
        'Message' => 'x',
        'Status' => $status < 300 ? 'Success' : 'Fail',
        'HttpStatus' => $status,
        'Data' => $data,
    ], $status);
}

it('posts a signed JSON body to handles/{operation} and returns Data', function (): void {
    Http::fake(['*/api/v1/internal/handles/reserve' => envelope([
        'handle' => 'acme', 'kind' => 'company', 'status' => 'reserved',
    ])]);

    $data = handles()->reserve('acme', HandleRegistryClient::KIND_COMPANY);

    expect($data['status'])->toBe('reserved');

    Http::assertSent(function (ClientRequest $request): bool {
        $headers = array_map(fn (array $v): string => $v[0], $request->headers());
        $expected = app(Signer::class)->sign($request->body(), (int) $headers[Signer::TIMESTAMP_HEADER]);

        return $request->url() === TokenFactory::ISSUER.'/api/v1/internal/handles/reserve'
            && $request->method() === 'POST'
            // nulls are dropped, never sent
            && $request->body() === '{"handle":"acme","kind":"company"}'
            && $headers[Signer::PROJECT_HEADER] === 'cc'
            && hash_equals($expected, $headers[Signer::SIGNATURE_HEADER]);
    });
});

it('reads check and release answers', function (): void {
    Http::fake([
        '*/handles/check' => envelope(['handle' => 'acme', 'available' => false]),
        '*/handles/release' => envelope(['handle' => 'acme', 'released' => true]),
    ]);

    expect(handles()->check('acme'))->toBeFalse()
        ->and(handles()->release('acme', 7))->toBeTrue();
});

it('maps each HDL code to its reason and keeps Auth\'s status', function (string $code, string $reason, int $status): void {
    Http::fake(['*/handles/confirm' => envelope(['error_code' => $code], $status)]);

    try {
        handles()->confirm('acme', 7);
        $this->fail('expected a refusal');
    } catch (HandleRegistryException $e) {
        expect($e->reason())->toBe($reason)
            ->and($e->status())->toBe($status)
            ->and($e->isUnavailable())->toBeFalse();
    }
})->with([
    ['HDL_001', HandleRegistryException::TAKEN, 409],
    ['HDL_002', HandleRegistryException::ALREADY_SET, 409],
    ['HDL_003', HandleRegistryException::NOT_RESERVED, 404],
    ['HDL_004', HandleRegistryException::USER_NOT_FOUND, 404],
    ['HDL_005', HandleRegistryException::ACCOUNT_REQUIRED, 422],
]);

it('reports an outage as unavailable, never as an answer', function (mixed $response): void {
    Http::fake(['*/handles/check' => $response]);

    expect(fn () => handles()->check('acme'))->toThrow(
        fn (HandleRegistryException $e) => expect($e->reason())->toBe(HandleRegistryException::UNAVAILABLE)
            ->and($e->status())->toBe(503)
    );
})->with([
    'connection refused' => fn () => fn () => throw new ConnectionException('refused'),
    'HTTP 502' => fn () => Http::response('bad gateway', 502),
    'unknown 4xx code' => fn () => envelope(['error_code' => 'INT_001'], 422),
    '200 without Data' => fn () => Http::response(['nope' => true], 200),
]);

it('is unavailable, not a crash, when there is no secret to sign with', function (): void {
    config()->set('wollerp-auth.hmac.outbound', '');
    app()->forgetInstance(Signer::class);
    Http::fake();

    expect(fn () => handles()->check('acme'))->toThrow(HandleRegistryException::class);
    Http::assertNothingSent();
});

it('copies handle from a full record into the mirror', function (): void {
    app(MirrorSynchroniser::class)->syncFromRecord([
        'auth_user_id' => 4217, 'auth_user_uuid' => TokenFactory::SUB,
        'email' => 'user@example.com', 'handle' => 'jane.smith', 'version' => 3,
    ]);

    expect(DB::table('users_mirror')->where('auth_user_id', 4217)->value('handle'))->toBe('jane.smith');
});

it('records a just-confirmed handle without touching version', function (): void {
    $mirror = app(MirrorSynchroniser::class);
    $mirror->syncFromRecord(['auth_user_id' => 4217, 'auth_user_uuid' => TokenFactory::SUB, 'version' => 3]);

    expect($mirror->syncHandle(4217, 'jane'))->toBeTrue()
        ->and($mirror->syncHandle(9999, 'nobody'))->toBeFalse();

    $row = DB::table('users_mirror')->where('auth_user_id', 4217)->first();
    expect($row->handle)->toBe('jane')->and((int) $row->version)->toBe(3);
});

it('keeps syncing a mirror that has no handle column yet', function (): void {
    Schema::table('users_mirror', function (Blueprint $table): void {
        $table->dropIndex(['handle']);
        $table->dropColumn('handle');
    });
    app()->forgetInstance(MirrorSynchroniser::class);
    $mirror = app(MirrorSynchroniser::class);

    expect($mirror->syncFromRecord([
        'auth_user_id' => 4217, 'auth_user_uuid' => TokenFactory::SUB,
        'email' => 'user@example.com', 'handle' => 'jane', 'version' => 3,
    ]))->toBeTrue()
        ->and($mirror->syncHandle(4217, 'jane'))->toBeFalse()
        ->and(DB::table('users_mirror')->where('auth_user_id', 4217)->value('email'))->toBe('user@example.com');
});
