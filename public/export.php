<?php

declare(strict_types=1);

use SslScanner\CsvExport;

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

$out = fopen('php://output', 'w');
CsvExport::write($out, $scan['results'], $only);
fclose($out);
