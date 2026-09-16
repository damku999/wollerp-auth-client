<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Wollerp\AuthClient\Mirror\MirroredUser;
use Wollerp\AuthClient\Tests\Support\TokenFactory;
use Wollerp\AuthClient\Tests\TestCase;

/**
 * `auth_user_id` is the real primary key and MirrorSynchroniser writes it by
 * name, so it cannot be renamed. `id` is Laravel's default route key, the
 * default `keyBy()` argument, and what everybody types from habit — so the
 * first `where('id', …)` in any consuming product is `Unknown column 'id'`.
 *
 * The alias used to be a hand-edit applied to the *published* migration, which
 * meant every consumer had to be told about it and `vendor:publish --force`
 * silently undid it. It is in the stub now, and these tests are what stop it
 * being dropped again.
 *
 * The harness runs the published stubs themselves (TestCase::migratePackageTables),
 * on SQLite, so this exercises the real generated column and not a fixture of one.
 */
function mirrorRowFromToken(array $overrides = []): void
{
    /** @var TestCase $test */
    $test = test();

    $test->mirror()->syncFromClaims(
        $test->validator()->validate($test->tokens->sign($test->tokens->payload($overrides)))
    );
}

it('exposes id as a generated alias of auth_user_id', function (): void {
    expect(Schema::hasColumn('users_mirror', 'id'))->toBeTrue();
});

it('answers a raw where(id) query, which is the failure the alias exists for', function (): void {
    mirrorRowFromToken();

    expect(DB::table('users_mirror')->where('id', TokenFactory::UID)->value('auth_user_uuid'))
        ->toBe(TokenFactory::SUB);
});

it('answers whereIn(id) and keyBy(id) through Eloquent', function (): void {
    // The cross-database chokepoint every product has some version of:
    // `User::whereIn('id', $ids)->get()->keyBy('id')`.
    mirrorRowFromToken();

    $keyed = MirroredUser::query()->whereIn('id', [TokenFactory::UID])->get()->keyBy('id');

    expect($keyed)->toHaveKey(TokenFactory::UID)
        ->and($keyed[TokenFactory::UID]->auth_user_uuid)->toBe(TokenFactory::SUB);
});

it('keeps id in step with auth_user_id across a ver-drift upsert', function (): void {
    // A generated column is computed on read. A stored copy written once at
    // insert time could drift on the upsert path, which is the path that runs
    // on every authenticated request.
    mirrorRowFromToken(['ver' => 11]);
    mirrorRowFromToken(['ver' => 12]);

    $row = DB::table('users_mirror')->where('id', TokenFactory::UID)->first();

    expect((int) $row->id)->toBe((int) $row->auth_user_id)
        ->and((int) $row->version)->toBe(12);
});

it('does not make the mirror writable through the alias', function (): void {
    // CONTRACT §4 still holds: `id` is a projection of the key, not a second
    // way in. The database itself refuses the write, below the model guard.
    mirrorRowFromToken();

    expect(fn () => DB::table('users_mirror')->where('id', TokenFactory::UID)->update(['id' => 9]))
        ->toThrow(QueryException::class);
});
