<?php

declare(strict_types=1);

namespace Wollerp\AuthClient\Console;

use Illuminate\Console\Command;
use Symfony\Component\Console\Attribute\AsCommand;
use Throwable;
use Wollerp\AuthClient\Conformance\CheckResult;
use Wollerp\AuthClient\Conformance\ConformanceSuite;
use Wollerp\AuthClient\Conformance\Report;

/**
 * INTEGRATION.md §8 check 1, as something a product can actually run.
 *
 * The checklist used to say "run `pest --testsuite=conformance` from inside
 * your app", which was impossible: Composer does not load a dependency's
 * `autoload-dev`, so the package's tests are not on a consumer's autoloader,
 * and the harness needs `orchestra/testbench` — a dev dependency a product has
 * no reason to install. The instruction was therefore skipped by default, which
 * is the worst property a security gate can have.
 *
 * This command has no test-framework dependency, ships in the runtime package,
 * needs no publishing step, and runs against the consumer's live configuration
 * including a warm `config:cache`. It makes no network calls, so it is safe on
 * a production host and deterministic in a CI job with no egress.
 *
 * Exit codes: 0 pass, 1 fail. Wire it into the pipeline, not into a runbook.
 *
 * `#[AsCommand]` for the same reason SyncUsersCommand carries it — Laravel only
 * defers instantiating commands that have it, and enumeration must not
 * construct the suite's dependencies at console boot.
 */
#[AsCommand(name: 'wollerp:conformance')]
final class ConformanceCommand extends Command
{
    protected $signature = 'wollerp:conformance
        {--strict : Treat posture warnings as failures. Use this in CI.}
        {--json : Emit the full report as JSON and nothing else.}
        {--quiet-passes : Print only failures, warnings and skips.}';

    protected $description = 'Verify this product validates Wollerp tokens correctly, against its own live configuration.';

    public function __construct(private readonly ConformanceSuite $suite)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $strict = (bool) $this->option('strict');

        try {
            $report = $this->suite->run($strict);
        } catch (Throwable $error) {
            // The suite catches per-check failures itself, so reaching here
            // means it could not start at all — almost always OpenSSL.
            $this->components->error('The conformance suite could not run: '.$error->getMessage());

            return self::FAILURE;
        }

        if ($this->option('json')) {
            $this->line((string) json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return $report->passed() ? self::SUCCESS : self::FAILURE;
        }

        $this->render($report);

        return $report->passed() ? self::SUCCESS : self::FAILURE;
    }

    private function render(Report $report): void
    {
        $this->newLine();
        $this->components->info(sprintf(
            'wollerp/auth-client conformance — issuer %s, audience %s%s',
            $report->issuer !== '' ? $report->issuer : '(unset)',
            $report->audience !== '' ? $report->audience : '(unset)',
            $report->strict ? ' [strict]' : '',
        ));

        $quiet = (bool) $this->option('quiet-passes');
        $group = null;

        foreach ($report->results as $result) {
            if ($quiet && $result->status === CheckResult::PASS) {
                continue;
            }

            if ($result->group !== $group) {
                $group = $result->group;
                $this->newLine();
                $this->line('  <fg=gray>'.strtoupper($group).'</>');
            }

            $this->line(sprintf(
                '  %s <fg=gray>%s</> %s',
                $this->badge($result->status),
                str_pad($result->id, 42),
                $result->title,
            ));

            if ($result->detail !== '' && $result->status !== CheckResult::PASS) {
                $this->line('      <fg=gray>'.wordwrap($result->detail, 96, "\n      ").'</>');
            }
        }

        $this->newLine();

        foreach ($report->failures() as $failure) {
            $this->newLine();
            $this->components->error($failure->id.' — '.$failure->title);
            $this->line('  '.wordwrap($failure->detail, 96, "\n  "));
            $this->line('  <fg=gray>Guards: '.wordwrap($failure->guards, 88, "\n          ").'</>');
        }

        $this->newLine();

        $summary = sprintf(
            '%d passed · %d failed · %d warned · %d skipped',
            count($report->passes()),
            count($report->failures()),
            count($report->warnings()),
            count($report->skipped()),
        );

        if ($report->passed()) {
            $this->components->info($summary);

            if ($report->warnings() !== []) {
                $this->components->warn(
                    'Warnings are not failures here, but they are in --strict. Run with --strict in CI '
                    .'once they are addressed.'
                );
            }

            return;
        }

        $this->components->error($summary.' — this product must not go to production in this state.');
    }

    private function badge(string $status): string
    {
        return match ($status) {
            CheckResult::PASS => '<fg=green>PASS</>',
            CheckResult::FAIL => '<fg=red;options=bold>FAIL</>',
            CheckResult::WARN => '<fg=yellow>WARN</>',
            default => '<fg=gray>SKIP</>',
        };
    }
}
