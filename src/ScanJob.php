<?php

declare(strict_types=1);

namespace SslScanner;

use InvalidArgumentException;

/**
 * Validates scan input and runs a scan, producing the "scan" record that the rest of
 * the app stores, displays, and exports. Shared by the web page and bin/run-saved.php.
 */
final class ScanJob
{
    public function __construct(
        private TargetParser $parser,
        private Scanner $scanner,
        private int $maxChecks,
    ) {
    }

    public static function fromConfig(): self
    {
        return new self(
            new TargetParser((int) config('max_hosts'), (int) config('max_ports')),
            new Scanner((float) config('timeout'), (int) config('concurrency')),
            (int) config('max_checks'),
        );
    }

    /**
     * Parses and checks the input (this is also where hostnames are resolved).
     *
     * @return array{targets: list<array>, ports: list<int>, warnings: list<string>, checks: int}
     * @throws ScanInputError when there's nothing valid to scan or the scan is too large
     */
    public function prepare(string $targetsInput, string $portsInput): array
    {
        try {
            $ports = $this->parser->parsePorts($portsInput);
            $parsed = $this->parser->parseTargets($targetsInput);
        } catch (InvalidArgumentException $e) {
            throw new ScanInputError($e->getMessage());
        }

        $checks = count($parsed['targets']) * count($ports);
        if ($parsed['targets'] === []) {
            throw new ScanInputError('No valid targets to scan.', $parsed['errors']);
        }
        if ($checks > $this->maxChecks) {
            throw new ScanInputError(
                "That would be {$checks} host/port checks; the limit is {$this->maxChecks}. Narrow the range or the port list.",
                $parsed['errors'],
            );
        }

        return ['targets' => $parsed['targets'], 'ports' => $ports, 'warnings' => $parsed['errors'], 'checks' => $checks];
    }

    /**
     * Runs a prepared scan.
     *
     * @param callable|null $onProgress see Scanner::scan()
     */
    public function run(array $prepared, string $targetsInput, string $portsInput, ?callable $onProgress = null): array
    {
        $started = microtime(true);
        $results = $this->scanner->scan($prepared['targets'], $prepared['ports'], $onProgress);
        self::sortResults($results);

        return [
            'at' => time(),
            'targets' => $targetsInput,
            'ports' => $portsInput,
            'warnings' => $prepared['warnings'],
            'elapsed' => microtime(true) - $started,
            'total' => $prepared['checks'],
            'cancelled' => $this->scanner->wasCancelled(),
            'results' => $results,
        ];
    }

    /** Certificates first, soonest expiry first; then failures by host, IP, and port. */
    public static function sortResults(array &$results): void
    {
        usort($results, static function (array $a, array $b): int {
            if ($a['ok'] !== $b['ok']) {
                return $a['ok'] ? -1 : 1;
            }
            if ($a['ok'] && $a['expires'] !== $b['expires']) {
                return $a['expires'] <=> $b['expires'];
            }
            return [$a['host'], inet_pton((string) $a['ip']) ?: '', $a['port']]
                <=> [$b['host'], inet_pton((string) $b['ip']) ?: '', $b['port']];
        });
    }
}
