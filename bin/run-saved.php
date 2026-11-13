<?php

declare(strict_types=1);

// Re-run a saved run from the command line, e.g. from cron.
// Run `php bin/run-saved.php --help` for usage.

use SslScanner\CsvExport;
use SslScanner\FileOwner;
use SslScanner\Report;
use SslScanner\ScanInputError;
use SslScanner\ScanJob;

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

const USAGE = <<<'TXT'
Usage:
  php bin/run-saved.php [options] "<saved run name>"
  php bin/run-saved.php [options] --id=<run id>
  php bin/run-saved.php --list [--user=<username>]

Re-scans the targets and ports of a saved run, saves the new results back to that run
(so the web page shows them), and prints a report of expired and expiring certificates
and what changed since the last run.

Options:
  --user=NAME      Owner of the saved run. Needed only if several users have a run
                   with the same name.
  --id=ID          Pick the run by id instead of name (ids are shown by --list and on
                   the Saved runs page). Ids don't change when a run is renamed.
  --quiet          Print nothing unless a certificate has expired or is expiring soon.
                   With cron, this means you only get email when action is needed.
  --all            Also list valid certificates in the report, not just problem ones.
  --warn-days=N    Treat certificates expiring within N days as "expiring"
                   (default: warn_days from config, currently %d).
  --csv=FILE       Also write the full results as CSV. "{date}" in the name is replaced
                   with the scan date, e.g. --csv=/var/reports/ssl-{date}.csv
  --no-save        Don't update the saved run; just scan and report.
  --list           List saved runs (name, id, owner, last scan) and exit.
  --help           Show this help.

Exit status:
  0  Nothing expired or expiring
  1  At least one certificate expires within the warning window
  2  At least one certificate has expired
  3  Error (run not found, already running, invalid targets, ...)

Example crontab line (as the web server user: sudo crontab -u www-data -e):
  0 7 * * *  php /var/www/php-ssl-scanner/bin/run-saved.php --quiet "Production"

TXT;

/** Prints to stderr and exits with the error status. */
function fail(string $message): never
{
    fwrite(STDERR, 'Error: ' . $message . PHP_EOL);
    exit(Report::ERROR);
}

// ---- Arguments ---------------------------------------------------------------------

$opts = ['user' => null, 'id' => null, 'quiet' => false, 'all' => false, 'warn-days' => null, 'csv' => null, 'no-save' => false, 'list' => false, 'help' => false];
$flags = ['quiet', 'all', 'no-save', 'list', 'help'];
$positional = [];

$args = array_slice($argv, 1);
while ($args !== []) {
    $arg = array_shift($args);
    if ($arg === '--') {
        array_push($positional, ...$args);
        break;
    }
    if (!str_starts_with($arg, '--')) {
        $positional[] = $arg;
        continue;
    }
    [$key, $value] = array_pad(explode('=', substr($arg, 2), 2), 2, null);
    if (!array_key_exists($key, $opts)) {
        fail("Unknown option --{$key}. Run with --help for usage.");
    }
    if (in_array($key, $flags, true)) {
        $opts[$key] = true;
        continue;
    }
    $value ??= array_shift($args);
    if ($value === null || $value === '') {
        fail("--{$key} needs a value.");
    }
    $opts[$key] = $value;
}

if ($opts['help']) {
    printf(USAGE, (int) config('warn_days'));
    exit(0);
}

$warnDays = (int) config('warn_days');
if ($opts['warn-days'] !== null) {
    if (!ctype_digit((string) $opts['warn-days'])) {
        fail('--warn-days must be a whole number of days.');
    }
    $warnDays = (int) $opts['warn-days'];
}

$problems = storage_problems();
if ($problems !== []) {
    fail(implode(' ', $problems) . PHP_EOL . cli_storage_advice());
}

$users = $opts['user'] !== null ? [$opts['user']] : users()->list();
if ($opts['user'] !== null && !users()->exists($opts['user'])) {
    fail("No user named \"{$opts['user']}\".");
}

// ---- --list -------------------------------------------------------------------------

if ($opts['list']) {
    $rows = [['NAME', 'ID', 'USER', 'LAST SCANNED (UTC)', 'CERTS', 'TARGETS']];
    foreach ($users as $u) {
        foreach (scans()->listRuns($u) as $run) {
            $targets = preg_replace('/\s+/', ' ', trim($run['targets']));
            $rows[] = [$run['name'], $run['id'], $u, gmdate('Y-m-d H:i', (int) $run['at']), (string) $run['found'], strlen($targets) > 40 ? substr($targets, 0, 37) . '...' : $targets];
        }
    }
    if (count($rows) === 1) {
        echo "No saved runs. Save a scan from the web page first.\n";
        exit(0);
    }
    $widths = [];
    foreach ($rows as $row) {
        foreach ($row as $i => $cell) {
            $widths[$i] = max($widths[$i] ?? 0, strlen($cell));
        }
    }
    foreach ($rows as $row) {
        echo rtrim(implode('  ', array_map(static fn ($c, $i) => str_pad($c, $widths[$i]), $row, array_keys($row)))), PHP_EOL;
    }
    exit(0);
}

// ---- Find the run -------------------------------------------------------------------

$matches = []; // list of [user, run summary]
if ($opts['id'] !== null) {
    foreach ($users as $u) {
        foreach (scans()->listRuns($u) as $run) {
            if ($run['id'] === $opts['id']) {
                $matches[] = [$u, $run];
            }
        }
    }
    $label = "id {$opts['id']}";
} else {
    if (count($positional) !== 1) {
        fwrite(STDERR, count($positional) === 0 ? "Which saved run? Give its name in quotes.\n\n" : "Give one run name. Put names with spaces in quotes.\n\n");
        fwrite(STDERR, sprintf(USAGE, (int) config('warn_days')));
        exit(Report::ERROR);
    }
    foreach ($users as $u) {
        foreach (scans()->findRunsByName($u, $positional[0]) as $run) {
            $matches[] = [$u, $run];
        }
    }
    $label = "\"{$positional[0]}\"";
}

if ($matches === []) {
    fail("No saved run named {$label}" . ($opts['user'] !== null ? " for user {$opts['user']}" : '') . '. Use --list to see saved runs.');
}
if (count($matches) > 1) {
    $lines = array_map(static fn ($m) => "  --user={$m[0]} --id={$m[1]['id']}  (last scanned " . gmdate('Y-m-d H:i', (int) $m[1]['at']) . ' UTC)', $matches);
    fail("More than one saved run matches {$label}. Pick one with:\n" . implode("\n", $lines));
}

[$user, $summary] = $matches[0];
$runId = $summary['id'];

// ---- Scan ---------------------------------------------------------------------------

$lock = scans()->lockRun($user, $runId);
if ($lock === null) {
    fail("\"{$summary['name']}\" is already being scanned by another process.");
}

$previous = scans()->loadRun($user, $runId);
if ($previous === null) {
    fail("Saved run {$label} disappeared before it could be loaded.");
}

$job = ScanJob::fromConfig();
try {
    $prepared = $job->prepare((string) $previous['targets'], (string) $previous['ports']);
} catch (ScanInputError $e) {
    fail("Can't scan \"{$previous['name']}\": " . $e->getMessage());
}

// Show progress when run by hand in a terminal; stay silent under cron.
$tty = function_exists('posix_isatty') ? posix_isatty(STDERR) : stream_isatty(STDERR);
$progress = $tty ? static function (int $done, int $total, int $found): void {
    fwrite(STDERR, sprintf("\rScanning: %d/%d checks, %d certificates found ", $done, $total, $found));
} : null;

$scan = $job->run($prepared, (string) $previous['targets'], (string) $previous['ports'], $progress);
if ($tty) {
    fwrite(STDERR, "\r" . str_repeat(' ', 60) . "\r");
}

// ---- Save and export ----------------------------------------------------------------

if (!$opts['no-save']) {
    scans()->updateRun($user, $runId, $scan, 'schedule');
    // If this run is the one showing on the user's scan page, refresh that too.
    if ((scans()->loadResult($user)['saved_id'] ?? null) === $runId) {
        scans()->saveResult($user, scans()->loadRun($user, $runId));
    }
}

if ($opts['csv'] !== null) {
    $path = str_replace('{date}', gmdate('Ymd-His', (int) $scan['at']), (string) $opts['csv']);
    $fh = @fopen($path, 'w');
    if ($fh === false) {
        fail("Could not write CSV to {$path}.");
    }
    CsvExport::write($fh, $scan['results']);
    fclose($fh);
    FileOwner::matchParent($path);
}

flock($lock, LOCK_UN);
fclose($lock);

// ---- Report -------------------------------------------------------------------------

$report = new Report($warnDays);
$status = $report->status($scan);

if (!$opts['quiet'] || $status !== Report::OK) {
    echo $report->render($previous['name'], $scan, $previous, $opts['all']);
}

exit($status);
