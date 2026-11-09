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
        }
    }

    private function writeJson(string $path, array $data): void
    {
        $this->ensureDir();
        // Write to a temp file and rename so readers never see a half-written file.
        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
        @chmod($tmp, 0600);
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
