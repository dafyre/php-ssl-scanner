<?php

declare(strict_types=1);

namespace SslScanner;

use InvalidArgumentException;

/**
 * File-based storage for in-progress scan status and each user's most recent results.
 *
 * Progress lives in files (not the PHP session) so the browser can poll it while the
 * scan request is still running, without fighting over the session lock.
 */
final class ScanStore
{
    private const STALE_AFTER = 86400;

    public function __construct(private string $dir)
    {
    }

    public static function isValidId(string $id): bool
    {
        return (bool) preg_match('/^[a-f0-9]{32}$/', $id);
    }

    public function writeProgress(string $user, string $id, array $state): void
    {
        $this->writeJson($this->progressPath($user, $id), $state + ['updated' => microtime(true)]);
    }

    public function readProgress(string $user, string $id): ?array
    {
        return $this->readJson($this->progressPath($user, $id));
    }

    public function requestCancel(string $user, string $id): void
    {
        $this->ensureDir();
        touch($this->progressPath($user, $id) . '.cancel');
        FileOwner::matchParent($this->progressPath($user, $id) . '.cancel');
    }

    public function cancelRequested(string $user, string $id): bool
    {
        return is_file($this->progressPath($user, $id) . '.cancel');
    }

    public function clearProgress(string $user, string $id): void
    {
        @unlink($this->progressPath($user, $id));
        @unlink($this->progressPath($user, $id) . '.cancel');
    }

    public function saveResult(string $user, array $scan): void
    {
        $this->writeJson($this->resultPath($user), $scan);
    }

    public function loadResult(string $user): ?array
    {
        return $this->readJson($this->resultPath($user));
    }

    // ---- Saved runs -------------------------------------------------------------

    public static function isValidRunId(string $id): bool
    {
        return (bool) preg_match('/^[a-f0-9]{16}$/', $id);
    }

    /** Saves a named copy of a scan and returns its id. */
    public function saveRun(string $user, array $scan, string $name): string
    {
        $scan = self::normalizeRun($scan);
        $name = self::cleanName($name) ?: ($scan['name'] ?: self::defaultName($scan));
        $id = bin2hex(random_bytes(8));
        $scan['name'] = $name;
        $scan['saved_at'] = time();

        $this->writeJson($this->runPath($user, $id), $scan);
        $this->mutateIndex($user, function (array $index) use ($id, $scan) {
            $index[$id] = self::summarize($id, $scan);
            return $index;
        });
        return $id;
    }

    /**
     * @return list<array{id: string, name: string, at: int, saved_at: int, targets: string, ports: string, checks: int, found: int, expires: list<int>, cancelled: bool}>
     */
    public function listRuns(string $user): array
    {
        $runs = array_values($this->readJson($this->indexPath($user)) ?? []);
        usort($runs, static fn ($a, $b) => $b['saved_at'] <=> $a['saved_at']);
        return $runs;
    }

    public function loadRun(string $user, string $id): ?array
    {
        if (!self::isValidRunId($id)) {
            return null;
        }
        $scan = $this->readJson($this->runPath($user, $id));
        return $scan === null ? null : $scan + ['saved_id' => $id];
    }

    /**
     * Saved runs with this name (case-insensitive, spacing ignored), newest first.
     *
     * @return list<array>
     */
    public function findRunsByName(string $user, string $name): array
    {
        $want = self::nameKey($name);
        return array_values(array_filter(
            $this->listRuns($user),
            static fn (array $run) => self::nameKey($run['name']) === $want,
        ));
    }

    /**
     * Replaces a saved run's results with a fresh scan, keeping its name and id.
     *
     * @param string $via what updated it, e.g. "schedule"; shown on the Saved runs page
     */
    public function updateRun(string $user, string $id, array $scan, string $via): bool
    {
        $existing = $this->loadRun($user, $id);
        if ($existing === null) {
            return false;
        }
        $scan = self::normalizeRun($scan);
        $scan['name'] = $existing['name'];
        $scan['saved_at'] = $existing['saved_at'] ?? time();
        $scan['updated_at'] = time();
        $scan['updated_via'] = $via;

        $this->writeJson($this->runPath($user, $id), $scan);
        $this->mutateIndex($user, function (array $index) use ($id, $scan) {
            $index[$id] = self::summarize($id, $scan);
            return $index;
        });
        return true;
    }

    /**
     * Takes an exclusive, non-blocking lock for a saved run so two scheduled runs of the
     * same job can't overlap. Returns the lock handle (keep it open), or null if it's held.
     *
     * @return resource|null
     */
    public function lockRun(string $user, string $id)
    {
        $this->ensureDir();
        $path = $this->runPath($user, $id) . '.lock';
        $fh = @fopen($path, 'c');
        if ($fh === false) {
            throw new \RuntimeException("Could not create lock file {$path}.");
        }
        FileOwner::matchParent($path);
        if (!flock($fh, LOCK_EX | LOCK_NB)) {
            fclose($fh);
            return null;
        }
        return $fh;
    }

    public function renameRun(string $user, string $id, string $name): bool
    {
        $scan = $this->loadRun($user, $id);
        $name = self::cleanName($name);
        if ($scan === null || $name === '') {
            return false;
        }
        unset($scan['saved_id']);
        $scan['name'] = $name;
        $this->writeJson($this->runPath($user, $id), $scan);
        $this->mutateIndex($user, function (array $index) use ($id, $name) {
            if (isset($index[$id])) {
                $index[$id]['name'] = $name;
            }
            return $index;
        });
        return true;
    }

    public function deleteRun(string $user, string $id): bool
    {
        if (!self::isValidRunId($id) || !is_file($this->runPath($user, $id))) {
            return false;
        }
        @unlink($this->runPath($user, $id));
        @unlink($this->runPath($user, $id) . '.lock');
        $this->mutateIndex($user, function (array $index) use ($id) {
            unset($index[$id]);
            return $index;
        });
        return true;
    }

    public static function defaultName(array $scan): string
    {
        $targets = preg_split('/[\s,;]+/', trim((string) ($scan['targets'] ?? '')), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $label = implode(', ', array_slice($targets, 0, 3)) . (count($targets) > 3 ? ', …' : '');
        return ($label !== '' ? $label : 'Scan') . ' — ' . gmdate('Y-m-d H:i', (int) ($scan['at'] ?? time())) . ' UTC';
    }

    /**
     * Validates and cleans a run, e.g. one uploaded as a JSON file, so the rest of the
     * app can trust its shape. Unknown keys are dropped.
     *
     * @throws InvalidArgumentException when the data isn't a scanner run
     */
    public static function normalizeRun(array $data): array
    {
        if (!isset($data['results']) || !is_array($data['results']) || !array_is_list($data['results'])) {
            throw new InvalidArgumentException('This file is not a saved scan: it has no results list.');
        }
        if (count($data['results']) > 100_000) {
            throw new InvalidArgumentException('This file has too many results to import.');
        }

        $str = static fn ($v, int $max = 1000): ?string => is_scalar($v) && (string) $v !== '' ? self::cut((string) $v, $max) : null;
        $int = static fn ($v): ?int => is_numeric($v) ? (int) $v : null;

        $results = [];
        foreach ($data['results'] as $i => $r) {
            if (!is_array($r)) {
                throw new InvalidArgumentException("Result #{$i} is not an object.");
            }
            $port = $int($r['port'] ?? null);
            $host = $str($r['host'] ?? null, 255);
            if ($host === null || $port === null || $port < 1 || $port > 65535) {
                throw new InvalidArgumentException("Result #{$i} is missing a valid host or port.");
            }
            $ip = $str($r['ip'] ?? null, 64);
            $ok = (bool) ($r['ok'] ?? false);
            $expires = $int($r['expires'] ?? null);
            if ($ok && $expires === null) {
                throw new InvalidArgumentException("Result #{$i} has a certificate but no expiry date.");
            }
            $sans = [];
            foreach ((array) ($r['sans'] ?? []) as $san) {
                if (($s = $str($san, 300)) !== null) {
                    $sans[] = $s;
                }
            }
            $results[] = [
                'host' => $host,
                'ip' => $ip !== null && filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null,
                'port' => $port,
                'sni' => $str($r['sni'] ?? null, 255),
                'ok' => $ok,
                'error' => $ok ? null : ($str($r['error'] ?? null, 300) ?? 'No certificate'),
                'cn' => $ok ? $str($r['cn'] ?? null, 300) : null,
                'sans' => $ok ? array_slice($sans, 0, 1000) : [],
                'issuer' => $ok ? $str($r['issuer'] ?? null, 300) : null,
                'self_signed' => $ok && (bool) ($r['self_signed'] ?? false),
                'issued' => $ok ? $int($r['issued'] ?? null) : null,
                'expires' => $ok ? $expires : null,
                'days_left' => $ok ? Scanner::daysLeft($expires) : null,
                'serial' => $ok ? $str($r['serial'] ?? null, 128) : null,
                'fingerprint' => $ok ? $str($r['fingerprint'] ?? null, 128) : null,
            ];
        }

        $warnings = [];
        foreach ((array) ($data['warnings'] ?? []) as $w) {
            if (($s = $str($w, 500)) !== null) {
                $warnings[] = $s;
            }
        }

        return [
            'name' => self::cleanName((string) ($data['name'] ?? '')),
            'at' => $int($data['at'] ?? null) ?? time(),
            'targets' => (string) $str($data['targets'] ?? '', 60_000),
            'ports' => (string) $str($data['ports'] ?? '', 1000),
            'warnings' => array_slice($warnings, 0, 100),
            'elapsed' => is_numeric($data['elapsed'] ?? null) ? (float) $data['elapsed'] : 0.0,
            'total' => $int($data['total'] ?? null) ?? count($results),
            'cancelled' => (bool) ($data['cancelled'] ?? false),
            'results' => $results,
        ];
    }

    /** The portable JSON form of a run, used for downloads and accepted by import. */
    public static function exportRun(array $scan): array
    {
        $run = self::normalizeRun($scan);
        return ['format' => 'php-ssl-scanner/run', 'version' => 1] + $run;
    }

    /** Unicode-safe truncation that doesn't require the mbstring extension. */
    private static function cut(string $s, int $max): string
    {
        if (function_exists('mb_substr')) {
            return mb_substr($s, 0, $max);
        }
        return preg_match('/^.{0,' . $max . '}/us', $s, $m) ? $m[0] : substr($s, 0, $max);
    }

    private static function nameKey(string $name): string
    {
        $name = self::cleanName($name);
        return function_exists('mb_strtolower') ? mb_strtolower($name) : strtolower($name);
    }

    private static function cleanName(string $name): string
    {
        $name = trim(preg_replace('/\s+/u', ' ', $name) ?? '');
        return self::cut($name, 120);
    }

    private static function summarize(string $id, array $scan): array
    {
        $expires = [];
        foreach ($scan['results'] as $r) {
            if ($r['ok']) {
                $expires[] = (int) $r['expires'];
            }
        }
        return [
            'id' => $id,
            'name' => $scan['name'],
            'at' => $scan['at'],
            'saved_at' => $scan['saved_at'],
            'targets' => self::cut($scan['targets'], 300),
            'ports' => $scan['ports'],
            'checks' => count($scan['results']),
            'found' => count($expires),
            'expires' => $expires, // kept so the list can show expired/expiring counts as of today
            'cancelled' => $scan['cancelled'],
            'updated_at' => $scan['updated_at'] ?? null,
            'updated_via' => $scan['updated_via'] ?? null,
        ];
    }

    private function runPath(string $user, string $id): string
    {
        if (!self::isValidRunId($id)) {
            throw new InvalidArgumentException('Invalid run id.');
        }
        return $this->dir . '/run-' . self::userKey($user) . '-' . $id . '.json';
    }

    private function indexPath(string $user): string
    {
        return $this->dir . '/runs-' . self::userKey($user) . '.json';
    }

    private function mutateIndex(string $user, callable $change): void
    {
        $this->ensureDir();
        $fh = fopen($this->indexPath($user), 'c+');
        if ($fh === false) {
            throw new \RuntimeException('Could not open the saved-runs index.');
        }
        try {
            flock($fh, LOCK_EX);
            $index = json_decode((string) stream_get_contents($fh), true);
            $index = $change(is_array($index) ? $index : []);
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, json_encode($index, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
            fflush($fh);
            @chmod($this->indexPath($user), 0600);
            FileOwner::matchParent($this->indexPath($user));
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    // ---- Maintenance --------------------------------------------------------------

    /** Remove progress files left behind by scans that died (e.g. killed by a server timeout). */
    public function cleanup(): void
    {
        foreach (glob($this->dir . '/progress-*') ?: [] as $file) {
            if (filemtime($file) < time() - self::STALE_AFTER) {
                @unlink($file);
            }
        }
    }

    private function progressPath(string $user, string $id): string
    {
        if (!self::isValidId($id)) {
            throw new InvalidArgumentException('Invalid scan id.');
        }
        return $this->dir . '/progress-' . self::userKey($user) . '-' . $id . '.json';
    }

    private function resultPath(string $user): string
    {
        return $this->dir . '/last-' . self::userKey($user) . '.json';
    }

    private static function userKey(string $user): string
    {
        return substr(hash('sha256', $user), 0, 24);
    }

    private function ensureDir(): void
    {
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0700, true);
            FileOwner::matchParent($this->dir);
        }
    }

    private function writeJson(string $path, array $data): void
    {
        $this->ensureDir();
        // Write to a temp file and rename so readers never see a half-written file.
        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
        @chmod($tmp, 0600);
        FileOwner::matchParent($tmp);
        rename($tmp, $path);
    }

    private function readJson(string $path): ?array
    {
        if (!is_file($path)) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($path), true);
        return is_array($data) ? $data : null;
    }
}
