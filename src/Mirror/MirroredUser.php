<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Mirror;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Wollerp\AuthClient\Exceptions\MirrorWriteForbiddenException;

/**
 * CONTRACT §4 — read-only projection of the auth server's user record.
 *
 * **No password column, ever.** The product database must never be able to
 * authenticate anyone; that is the auth server's job and only its job. There is
 * no password attribute here and the migration does not create the column.
 *
 * Every write path through this model throws. That is the contract's "enforce
 * with a model guard that throws, not a code-review convention". The only
 * legitimate writer is MirrorSynchroniser, which opens the gate for the
 * duration of its own upsert.
 *
 * @property int $auth_user_id
 * @property string $auth_user_uuid
 * @property string|null $name
 * @property string|null $email
 * @property string|null $status
 * @property \Illuminate\Support\Carbon|null $email_verified_at
 * @property int $version
 * @property \Illuminate\Support\Carbon|null $synced_at
 */
class MirroredUser extends Model implements Authenticatable
{
    public $timestamps = false;

    public $incrementing = false;

    protected $primaryKey = 'auth_user_id';

    protected $keyType = 'int';

    /**
     * Unguarded on purpose: the write guard below is the real control, and it
     * is absolute. A fillable list here would imply some writes are fine.
     */
    protected $guarded = [];

    protected static ?string $mirrorConnection = null;

    protected static string $mirrorTable = 'users_mirror';

    /**
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        $this->setTable(static::$mirrorTable);
        $this->setConnection(static::$mirrorConnection);
    }

    /**
     * Called once by the service provider from the published config.
     */
    public static function configureStorage(?string $connection, string $table): void
    {
        static::$mirrorConnection = $connection;
        static::$mirrorTable = $table;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'auth_user_id' => 'integer',
            'version' => 'integer',
            'email_verified_at' => 'datetime',
            'synced_at' => 'datetime',
        ];
    }

    /**
     * The write guard, deliberately implemented as method overrides rather than
     * `saving`/`deleting` model events.
     *
     * Events are the obvious choice and the wrong one: `saveQuietly()`,
     * `deleteQuietly()` and `withoutEvents()` all suppress them, so an
     * event-based guard is bypassed by a one-word change. Overriding save() and
     * delete() catches the quiet variants too, because both funnel through
     * here.
     *
     * What this cannot catch is a raw query-builder write —
     * `DB::table('users_mirror')->update(...)`. Nothing in PHP can. That is the
     * residual risk, and it is why the table is named for what it is.
     *
     * @param  array<string, mixed>  $options
     */
    public function save(array $options = []): bool
    {
        $this->assertSynchroniserIsWriting('save');

        return parent::save($options);
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function saveOrFail(array $options = []): bool
    {
        $this->assertSynchroniserIsWriting('save');

        return parent::saveOrFail($options);
    }

    public function delete(): ?bool
    {
        $this->assertSynchroniserIsWriting('delete');

        return parent::delete();
    }

    private function assertSynchroniserIsWriting(string $operation): void
    {
        if (! MirrorSynchroniser::isSynchronising()) {
            throw MirrorWriteForbiddenException::for($operation, static::class);
        }
    }

    // ── Authenticatable ──────────────────────────────────────────────────────
    // Enough for `auth:wollerp` to hand a product `$request->user()->auth_user_id`.
    // No credential surface: there is no password and no remember token.

    public function getAuthIdentifierName(): string
    {
        return 'auth_user_id';
    }

    public function getAuthIdentifier(): int
    {
        return (int) $this->getAttribute('auth_user_id');
    }

    public function getAuthPasswordName(): string
    {
        return '';
    }

    /**
     * Always empty. Nothing may ever authenticate against the mirror — the
     * empty string cannot match any hash, so a misrouted Hash::check() fails
     * closed rather than silently comparing against a stale credential.
     */
    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): string
    {
        return '';
    }

    public function setRememberToken($value): void
    {
        // No-op. Session persistence is not a thing for a bearer-token guard.
    }

    public function getRememberTokenName(): string
    {
        return '';
    }
}
