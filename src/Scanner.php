<?php

declare(strict_types=1);

namespace SslScanner;

/**
 * Connects to many host:port pairs in parallel, performs a TLS handshake, and
 * captures the certificate each one presents.
 *
 * Certificate validation is deliberately disabled: the goal is to report what a
 * server presents (including expired or self-signed certificates), not to trust it.
 */
final class Scanner
{
    private const PROGRESS_INTERVAL = 0.25;

    private bool $cancelled = false;

    public function __construct(
        private float $timeout = 4.0,
        private int $concurrency = 64,
    ) {
    }

    /**
     * @param list<array{label: string, ip: ?string, sni: ?string, error: ?string}> $targets
     * @param list<int> $ports
     * @param (callable(int $done, int $total, int $found): bool|void)|null $onProgress
     *        Called periodically and once at the end. Return false to cancel the scan;
     *        checks still in flight are abandoned and only finished results are returned.
     * @return list<array<string, mixed>>
     */
    public function scan(array $targets, array $ports, ?callable $onProgress = null): array
    {
        $this->cancelled = false;
        $queue = [];
        $results = [];
        foreach ($targets as $t) {
            foreach ($ports as $port) {
                $base = ['host' => $t['label'], 'ip' => $t['ip'], 'port' => $port, 'sni' => $t['sni']];
                if ($t['error'] !== null) {
                    $results[] = self::failure($base, $t['error']);
                } else {
                    $queue[] = $base;
                }
            }
        }

        $total = count($results) + count($queue);
        $next = 0;
        $lastReport = 0.0;

        /** @var array<int, array{job: array, stream: resource, phase: string, deadline: float}> $active */
        $active = [];

        while ($next < count($queue) || $active !== []) {
            if ($onProgress !== null && microtime(true) - $lastReport >= self::PROGRESS_INTERVAL) {
                $lastReport = microtime(true);
                if ($onProgress(count($results), $total, self::countFound($results)) === false) {
                    $this->cancelled = true;
                    foreach ($active as $conn) {
                        fclose($conn['stream']);
                    }
                    return $results;
                }
            }

            while ($next < count($queue) && count($active) < $this->concurrency) {
                $job = $queue[$next++];
                $stream = $this->open($job, $error);
                if ($stream === null) {
                    $results[] = self::failure($job, $error);
                    continue;
                }
                $active[(int) $stream] = [
                    'job' => $job,
                    'stream' => $stream,
                    'phase' => 'connect',
                    'deadline' => microtime(true) + $this->timeout,
                ];
            }

            $read = [];
            $write = [];
            foreach ($active as $conn) {
                if ($conn['phase'] === 'connect') {
                    $write[] = $conn['stream'];
                } else {
                    $read[] = $conn['stream'];
                }
            }
            $except = null;
            if ($read !== [] || $write !== []) {
                @stream_select($read, $write, $except, 0, 100_000);
            }

            foreach ($write as $stream) {
                $id = (int) $stream;
                if (stream_socket_get_name($stream, true) === false) {
                    $results[] = self::failure($active[$id]['job'], 'Connection refused or unreachable');
                    fclose($stream);
                    unset($active[$id]);
                    continue;
                }
                $active[$id]['phase'] = 'tls';
                $active[$id]['deadline'] = microtime(true) + $this->timeout;
                $this->stepHandshake($active, $id, $results);
            }

            foreach ($read as $stream) {
                $id = (int) $stream;
                if (isset($active[$id])) {
                    $this->stepHandshake($active, $id, $results);
                }
            }

            $now = microtime(true);
            foreach ($active as $id => $conn) {
                if ($now >= $conn['deadline']) {
                    $msg = $conn['phase'] === 'connect' ? 'Connection timed out' : 'TLS handshake timed out';
                    $results[] = self::failure($conn['job'], $msg);
                    fclose($conn['stream']);
                    unset($active[$id]);
                }
            }
        }

        if ($onProgress !== null) {
            $onProgress(count($results), $total, self::countFound($results));
        }

        return $results;
    }

    /** Whether the most recent scan() was stopped early by the progress callback. */
    public function wasCancelled(): bool
    {
        return $this->cancelled;
    }

    /** Whole days remaining; once expired, a negative count of whole days since (at least -1). */
    public static function daysLeft(int $expires, ?int $now = null): int
    {
        $now ??= time();
        return $expires >= $now
            ? intdiv($expires - $now, 86400)
            : -max(1, intdiv($now - $expires, 86400));
    }

    private static function countFound(array $results): int
    {
        return count(array_filter($results, static fn ($r) => $r['ok']));
    }

    /**
     * @return resource|null
     */
    private function open(array $job, ?string &$error)
    {
        $ssl = [
            'capture_peer_cert' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            // Accept legacy protocols/ciphers so old appliances still report their certificates.
            'ciphers' => 'DEFAULT:@SECLEVEL=0',
            'SNI_enabled' => $job['sni'] !== null,
        ];
        if ($job['sni'] !== null) {
            $ssl['peer_name'] = $job['sni'];
        }

        $host = str_contains((string) $job['ip'], ':') ? "[{$job['ip']}]" : $job['ip'];
        $context = stream_context_create(['ssl' => $ssl]);
        $stream = @stream_socket_client(
            "tcp://{$host}:{$job['port']}",
            $errno,
            $errstr,
            $this->timeout,
            STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT,
            $context,
        );

        if ($stream === false) {
            $error = $errstr !== '' ? $errstr : 'Could not open socket';
            return null;
        }

        stream_set_blocking($stream, false);
        return $stream;
    }

    private function stepHandshake(array &$active, int $id, array &$results): void
    {
        $conn = $active[$id];
        error_clear_last();
        $status = @stream_socket_enable_crypto($conn['stream'], true, STREAM_CRYPTO_METHOD_TLS_CLIENT);

        if ($status === 0) {
            return; // Handshake still in progress; wait for more data.
        }

        if ($status === true) {
            $params = stream_context_get_params($conn['stream']);
            $cert = $params['options']['ssl']['peer_certificate'] ?? null;
            $results[] = $cert
                ? self::success($conn['job'], $cert)
                : self::failure($conn['job'], 'Handshake succeeded but no certificate was presented');
        } else {
            $results[] = self::failure($conn['job'], self::handshakeError());
        }

        fclose($conn['stream']);
        unset($active[$id]);
    }

    private static function handshakeError(): string
    {
        // PHP rarely surfaces OpenSSL's reason for non-blocking handshakes, so
        // fall back to a generic hint when nothing more specific is available.
        $message = error_get_last()['message'] ?? '';
        if ($message !== '' && preg_match('/error:[0-9A-F]+:[^:]*:[^:]*:(\S.*)$/', $message, $m)) {
            return 'TLS handshake failed: ' . $m[1];
        }
        return 'Port is open but the TLS handshake failed (service may not use TLS)';
    }

    /**
     * @param \OpenSSLCertificate $cert
     */
    private static function success(array $job, $cert): array
    {
        $info = openssl_x509_parse($cert) ?: [];
        $cn = $info['subject']['CN'] ?? null;
        $issuerCn = $info['issuer']['CN'] ?? null;
        $issuerOrg = $info['issuer']['O'] ?? null;

        $sans = [];
        foreach (explode(',', $info['extensions']['subjectAltName'] ?? '') as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            [$type, $value] = array_pad(explode(':', $entry, 2), 2, '');
            $sans[] = match (trim($type)) {
                'DNS' => $value,
                'IP Address' => 'IP:' . trim($value),
                default => trim($type) . ':' . trim($value),
            };
        }

        $issued = (int) ($info['validFrom_time_t'] ?? 0);
        $expires = (int) ($info['validTo_time_t'] ?? 0);

        return $job + [
            'ok' => true,
            'error' => null,
            'cn' => is_array($cn) ? implode(', ', $cn) : $cn,
            'sans' => $sans,
            'issuer' => is_array($issuerCn) ? implode(', ', $issuerCn) : ($issuerCn ?? (is_array($issuerOrg) ? implode(', ', $issuerOrg) : $issuerOrg)),
            'self_signed' => ($info['subject'] ?? null) == ($info['issuer'] ?? null),
            'issued' => $issued,
            'expires' => $expires,
            'days_left' => self::daysLeft($expires),
            'serial' => $info['serialNumberHex'] ?? null,
            'fingerprint' => openssl_x509_fingerprint($cert, 'sha256') ?: null,
        ];
    }

    private static function failure(array $job, string $error): array
    {
        return $job + [
            'ok' => false,
            'error' => $error,
            'cn' => null,
            'sans' => [],
            'issuer' => null,
            'self_signed' => false,
            'issued' => null,
            'expires' => null,
            'days_left' => null,
            'serial' => null,
            'fingerprint' => null,
        ];
    }
}
