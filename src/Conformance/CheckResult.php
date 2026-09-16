<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Conformance;

use JsonSerializable;

/**
 * The outcome of one conformance check.
 *
 * `severity` is a property of the CHECK, not of the run: a pin check guards a
 * complete authentication bypass and is fatal wherever it runs, with no flag to
 * downgrade it. A posture check describes availability or operational hygiene
 * and warns by default; `--strict` promotes those warnings to failures.
 */
final class CheckResult implements JsonSerializable
{
    public const PASS = 'pass';

    public const FAIL = 'fail';

    public const WARN = 'warn';

    public const SKIP = 'skip';

    /** Guards a bypass. Always fatal. */
    public const PIN = 'pin';

    /** Guards availability or hygiene. Warns unless the run is strict. */
    public const POSTURE = 'posture';

    private function __construct(
        public readonly string $id,
        public readonly string $group,
        public readonly string $severity,
        public readonly string $status,
        public readonly string $title,
        public readonly string $guards,
        public readonly string $detail,
    ) {}

    /**
     * @param  array{id: string, group: string, severity: string, title: string, guards: string}  $check
     */
    public static function pass(array $check, string $detail = ''): self
    {
        return new self(
            $check['id'], $check['group'], $check['severity'],
            self::PASS, $check['title'], $check['guards'], $detail,
        );
    }

    /**
     * @param  array{id: string, group: string, severity: string, title: string, guards: string}  $check
     */
    public static function fail(array $check, string $detail): self
    {
        return new self(
            $check['id'], $check['group'], $check['severity'],
            $check['severity'] === self::PIN ? self::FAIL : self::WARN,
            $check['title'], $check['guards'], $detail,
        );
    }

    /**
     * @param  array{id: string, group: string, severity: string, title: string, guards: string}  $check
     */
    public static function skip(array $check, string $detail): self
    {
        return new self(
            $check['id'], $check['group'], $check['severity'],
            self::SKIP, $check['title'], $check['guards'], $detail,
        );
    }

    public function isPin(): bool
    {
        return $this->severity === self::PIN;
    }

    /**
     * A warning counts as a failure only when the run asked for it.
     */
    public function failedUnder(bool $strict): bool
    {
        return $this->status === self::FAIL || ($strict && $this->status === self::WARN);
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'group' => $this->group,
            'severity' => $this->severity,
            'status' => $this->status,
            'title' => $this->title,
            'guards' => $this->guards,
            'detail' => $this->detail,
        ];
    }
}
