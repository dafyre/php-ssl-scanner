<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

// GET exports every row of the current results. POST (from the filter bar) can limit the
// export to the rows on screen: "rows" is a comma-separated list of result indexes.

$user = require_login();

$only = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valid()) {
        http_response_code(403);
        exit('Your session expired. Reload the page and try again.');
    }
    $rows = trim((string) ($_POST['rows'] ?? ''));
    if ($rows !== '') {
        $only = $rows === 'none' ? [] : array_flip(array_map('intval', explode(',', $rows)));
    }
}
session_write_close();

$scan = scans()->loadResult($user);
if ($scan === null) {
    header('Location: index.php');
    exit;
}

// The row indexes refer to the results that were on screen. If another scan has
// finished since then (e.g. in another tab), they'd point at the wrong rows.
if ($only !== null && (int) ($_POST['scan_at'] ?? 0) !== (int) $scan['at']) {
    http_response_code(409);
    exit('These results have been replaced by a newer scan. Reload the page and export again.');
}

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="ssl-scan-' . gmdate('Ymd-His', $scan['at']) . ($only !== null ? '-filtered' : '') . '.csv"');
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

foreach ($scan['results'] as $i => $r) {
    if ($only !== null && !isset($only[$i])) {
        continue;
    }
    if ($r['ok']) {
        $r['days_left'] = SslScanner\Scanner::daysLeft((int) $r['expires']);
    }
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
