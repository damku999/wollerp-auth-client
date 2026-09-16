<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Conformance;

use JsonSerializable;

/**
 * The outcome of a conformance run.
 *
 * `passed()` is the only thing a caller needs: CI asserts it, the artisan
 * command exits on it, and a consumer's own test suite asserts it in one line.
 */
final class Report implements JsonSerializable
{
    /**
     * @param  list<CheckResult>  $results
     */
    public function __construct(
        public readonly array $results,
        public readonly bool $strict,
        public readonly string $issuer,
        public readonly string $audience,
    ) {}

    public function passed(): bool
    {
        return $this->failures() === [];
    }

    /**
     * @return list<CheckResult>
     */
    public function failures(): array
    {
        return array_values(array_filter(
            $this->results,
            fn (CheckResult $result): bool => $result->failedUnder($this->strict),
        ));
    }

    /**
     * @return list<CheckResult>
     */
    public function warnings(): array
    {
        return $this->withStatus(CheckResult::WARN);
    }

    /**
     * @return list<CheckResult>
     */
    public function skipped(): array
    {
        return $this->withStatus(CheckResult::SKIP);
    }

    /**
     * @return list<CheckResult>
     */
    public function passes(): array
    {
        return $this->withStatus(CheckResult::PASS);
    }

    /**
     * Every check id that actually executed. The suite compares this against
     * its own manifest so a deleted check is itself a failure.
     *
     * @return list<string>
     */
    public function executedIds(): array
    {
        return array_values(array_map(
            fn (CheckResult $result): string => $result->id,
            $this->results,
        ));
    }

    /**
     * One line per failure, loud enough to paste into an incident channel.
     */
    public function failureSummary(): string
    {
        return implode("\n", array_map(
            fn (CheckResult $result): string => sprintf(
                '[%s] %s — %s',
                $result->id,
                $result->title,
                $result->detail,
            ),
            $this->failures(),
        ));
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'passed' => $this->passed(),
            'strict' => $this->strict,
            'issuer' => $this->issuer,
            'audience' => $this->audience,
            'totals' => [
                'checks' => count($this->results),
                'passed' => count($this->passes()),
                'failed' => count($this->failures()),
                'warned' => count($this->warnings()),
                'skipped' => count($this->skipped()),
            ],
            'checks' => array_map(
                fn (CheckResult $result): array => $result->jsonSerialize(),
                $this->results,
            ),
        ];
    }

    /**
     * @return list<CheckResult>
     */
    private function withStatus(string $status): array
    {
        return array_values(array_filter(
            $this->results,
            fn (CheckResult $result): bool => $result->status === $status,
        ));
    }
}
