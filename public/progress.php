<?php

declare(strict_types=1);

// Progress for a running scan, polled by the scan page.
//   GET  progress.php?id=<scan id>                 -> JSON status
//   POST progress.php  id=<scan id>&csrf=<token>   -> request cancellation

use SslScanner\ScanStore;

require dirname(__DIR__) . '/src/bootstrap.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

// Read-only session: never write it back, so polling can't clobber the scan request's session.
$user = current_user(true);
if ($user === null) {
    http_response_code(401);
    echo json_encode(['status' => 'unauthenticated']);
    exit;
}

$id = (string) ($_SERVER['REQUEST_METHOD'] === 'POST' ? ($_POST['id'] ?? '') : ($_GET['id'] ?? ''));
if (!ScanStore::isValidId($id)) {
    http_response_code(400);
    echo json_encode(['status' => 'invalid']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valid()) {
        http_response_code(403);
        echo json_encode(['status' => 'forbidden']);
        exit;
    }
    scans()->requestCancel($user, $id);
    echo json_encode(['status' => 'cancelling']);
    exit;
}

// No progress file means the scan hasn't started writing yet, or has just finished.
$state = scans()->readProgress($user, $id) ?? ['status' => 'unknown'];
if (scans()->cancelRequested($user, $id) && ($state['status'] ?? '') === 'scanning') {
    $state['status'] = 'cancelling';
}
echo json_encode($state);
