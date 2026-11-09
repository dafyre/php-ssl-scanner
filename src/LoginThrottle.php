<?php

declare(strict_types=1);

namespace SslScanner;

/**
 * Locks out an IP address after too many failed logins within a time window.
 */
final class LoginThrottle
{
    public function __construct(
        private string $file,
        private int $maxAttempts = 5,
        private int $window = 900,
    ) {
    }

    /** Seconds until this IP may try again, or 0 if it is not locked out. */
    public function lockedFor(string $ip): int
    {
        $attempts = $this->recent($this->load()[$ip] ?? []);
        if (count($attempts) < $this->maxAttempts) {
            return 0;
        }
        return max(1, min($attempts) + $this->window - time());
    }

    public function recordFailure(string $ip): void
    {
        $this->mutate(function (array $data) use ($ip) {
            $data[$ip] = $this->recent($data[$ip] ?? []);
            $data[$ip][] = time();
            return $data;
        });
    }

    public function clear(string $ip): void
    {
        $this->mutate(function (array $data) use ($ip) {
            unset($data[$ip]);
            return $data;
        });
    }

    private function recent(array $times): array
    {
        $cutoff = time() - $this->window;
        return array_values(array_filter($times, static fn ($t) => $t > $cutoff));
    }

    private function load(): array
    {
        if (!is_file($this->file)) {
            return [];
        }
        $data = json_decode((string) file_get_contents($this->file), true);
        return is_array($data) ? $data : [];
    }

    private function mutate(callable $change): void
    {
        $dir = dirname($this->file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        $fh = @fopen($this->file, 'c+');
        if ($fh === false) {
            return;
        }
        try {
            flock($fh, LOCK_EX);
            $data = json_decode((string) stream_get_contents($fh), true);
            $data = $change(is_array($data) ? $data : []);
            // Drop entries for IPs with no recent failures.
            $data = array_filter(array_map(fn ($t) => $this->recent($t), $data));
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, json_encode($data));
            fflush($fh);
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }
}
