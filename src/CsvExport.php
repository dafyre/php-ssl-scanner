<?php

declare(strict_types=1);

namespace SslScanner;

/** Writes scan results as CSV. Used by the web download and bin/run-saved.php --csv. */
final class CsvExport
{
    public const HEADER = ['host', 'ip', 'port', 'status', 'common_name', 'san', 'issuer', 'self_signed', 'issued_utc', 'expires_utc', 'days_left', 'serial', 'sha256_fingerprint', 'error'];

    /**
     * @param resource $out
     * @param array<int, mixed>|null $only result indexes to include (as keys), or null for all
     */
    public static function write($out, array $results, ?array $only = null): void
    {
        fputcsv($out, self::HEADER, ',', '"', '');
        foreach ($results as $i => $r) {
            if ($only !== null && !isset($only[$i])) {
                continue;
            }
            if ($r['ok']) {
                $r['days_left'] = Scanner::daysLeft((int) $r['expires']);
            }
            fputcsv($out, array_map([self::class, 'safe'], [
                $r['host'],
                $r['ip'] ?? '',
                $r['port'],
                $r['ok'] ? ($r['days_left'] < 0 ? 'expired' : 'ok') : 'no_certificate',
                $r['cn'] ?? '',
                implode('; ', $r['sans']),
                $r['issuer'] ?? '',
                $r['ok'] ? ($r['self_signed'] ? 'yes' : 'no') : '',
                $r['issued'] ? gmdate('Y-m-d H:i:s', $r['issued']) : '',
                $r['expires'] ? gmdate('Y-m-d H:i:s', $r['expires']) : '',
                $r['days_left'] ?? '',
                $r['serial'] ?? '',
                $r['fingerprint'] ?? '',
                $r['error'] ?? '',
            ]), ',', '"', '');
        }
    }

    /** Prevent spreadsheet formula injection from certificate fields. */
    public static function safe(mixed $value): string
    {
        if (is_int($value)) {
            return (string) $value;
        }
        $value = (string) $value;
        return preg_match('/^[=+\-@\t\r]/', $value) ? "'" . $value : $value;
    }
}
