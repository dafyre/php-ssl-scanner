<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

require_login();

$scan = $_SESSION['last_scan'] ?? null;
if ($scan === null) {
    header('Location: index.php');
    exit;
}

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="ssl-scan-' . gmdate('Ymd-His', $scan['at']) . '.csv"');
header('X-Content-Type-Options: nosniff');

/** Prevent spreadsheet formula injection from certificate fields. */
function csv_safe(mixed $value): string
{
    if (is_int($value)) {
        return (string) $value;
    }
    $value = (string) $value;
    return preg_match('/^[=+\-@\t\r]/', $value) ? "'" . $value : $value;
}

$out = fopen('php://output', 'w');
fputcsv($out, ['host', 'ip', 'port', 'status', 'common_name', 'san', 'issuer', 'self_signed', 'issued_utc', 'expires_utc', 'days_left', 'serial', 'sha256_fingerprint', 'error']);

foreach ($scan['results'] as $r) {
    fputcsv($out, array_map('csv_safe', [
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
    ]));
}
fclose($out);
