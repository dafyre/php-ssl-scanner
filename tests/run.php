<?php

declare(strict_types=1);

// Minimal dependency-free tests: php tests/run.php

require dirname(__DIR__) . '/src/bootstrap.php';

use SslScanner\Scanner;
use SslScanner\ScanStore;
use SslScanner\TargetParser;

$failures = 0;
function check(string $name, bool $ok): void
{
    global $failures;
    echo ($ok ? "  ok   " : "  FAIL ") . $name . PHP_EOL;
    $failures += $ok ? 0 : 1;
}
function throws(callable $fn): bool
{
    try {
        $fn();
        return false;
    } catch (InvalidArgumentException) {
        return true;
    }
}

$fakeDns = static fn (string $h): array => match ($h) {
    'example.com' => ['93.184.216.34'],
    'multi.test' => ['10.0.0.1', '10.0.0.2'],
    default => [],
};
$p = new TargetParser(1024, 64, $fakeDns);

echo "Ports\n";
check('single ports', $p->parsePorts('443, 8443') === [443, 8443]);
check('ranges and dedupe', $p->parsePorts('443 440-442,443') === [440, 441, 442, 443]);
check('reversed range', $p->parsePorts('12-10') === [10, 11, 12]);
check('rejects port 0', throws(fn () => $p->parsePorts('0')));
check('rejects port 65536', throws(fn () => $p->parsePorts('65536')));
check('rejects junk', throws(fn () => $p->parsePorts('https')));
check('rejects huge range', throws(fn () => $p->parsePorts('1-1000')));

echo "CIDR\n";
check('/24 has 254 hosts', count($p->expandCidr('192.168.1.0/24')) === 254);
check('/24 skips network and broadcast', ($ips = $p->expandCidr('192.168.1.0/24'))[0] === '192.168.1.1' && end($ips) === '192.168.1.254');
check('non-aligned /30 normalizes to its network', $p->expandCidr('10.1.2.78/30') === ['10.1.2.77', '10.1.2.78']);
check('/31 keeps both', $p->expandCidr('10.0.0.0/31') === ['10.0.0.0', '10.0.0.1']);
check('/32 single host', $p->expandCidr('10.0.0.5/32') === ['10.0.0.5']);
check('crosses octet boundary', count($p->expandCidr('10.0.0.0/23')) === 510);
check('IPv6 /126', $p->expandCidr('2001:db8::/126') === ['2001:db8::', '2001:db8::1', '2001:db8::2', '2001:db8::3']);
check('rejects /16 (too many)', throws(fn () => $p->expandCidr('10.0.0.0/16')));
check('rejects bad prefix', throws(fn () => $p->expandCidr('10.0.0.0/33')));
check('rejects bad address', throws(fn () => $p->expandCidr('10.0.0.300/24')));

echo "Targets\n";
$r = $p->parseTargets("example.com, 10.0.0.9\n multi.test nope.invalid bad_host!");
$labels = array_map(fn ($t) => $t['label'] . '=' . ($t['ip'] ?? 'null'), $r['targets']);
check('hostname resolves with SNI', $r['targets'][0] === ['label' => 'example.com', 'ip' => '93.184.216.34', 'sni' => 'example.com', 'error' => null]);
check('IP has no SNI', $r['targets'][1]['sni'] === null);
check('all A records scanned', in_array('multi.test=10.0.0.1', $labels, true) && in_array('multi.test=10.0.0.2', $labels, true));
check('unresolvable host reported', in_array('nope.invalid=null', $labels, true));
check('invalid token warned', count($r['errors']) === 1 && str_contains($r['errors'][0], 'bad_host!'));
check('duplicates removed', count($p->parseTargets('10.0.0.1 10.0.0.1 10.0.0.0/30')['targets']) === 2);
check('empty input rejected', throws(fn () => $p->parseTargets('   ')));
check('host limit enforced', throws(fn () => (new TargetParser(10, 64, $fakeDns))->parseTargets('10.0.0.0/28')));

echo "Scanner\n";

$now = 1_800_000_000;
check('daysLeft counts whole days remaining', Scanner::daysLeft($now + 86400 * 19 + 3600, $now) === 19);
check('daysLeft is 0 on the last day', Scanner::daysLeft($now + 60, $now) === 0);
check('daysLeft is -1 just after expiry', Scanner::daysLeft($now - 60, $now) === -1);
check('daysLeft counts days since expiry', Scanner::daysLeft($now - 86400 * 3 - 60, $now) === -3);

$targets = [['label' => '127.0.0.1', 'ip' => '127.0.0.1', 'sni' => null, 'error' => null]];
$calls = [];
$scanner = new Scanner(1.0, 4);
$res = $scanner->scan($targets, [1, 2, 3], function ($done, $total, $found) use (&$calls) {
    $calls[] = [$done, $total, $found];
    return false;
});
check('progress callback can cancel', $scanner->wasCancelled() && $res === [] && $calls === [[0, 3, 0]]);

$calls = [];
$res = $scanner->scan([['label' => 'x.invalid', 'ip' => null, 'sni' => 'x.invalid', 'error' => 'DNS lookup failed']], [443, 8443], function ($d, $t, $f) use (&$calls) {
    $calls[] = [$d, $t, $f];
});
check('final progress report is complete', !$scanner->wasCancelled() && end($calls) === [2, 2, 0] && count($res) === 2);

echo "ScanStore\n";
$dir = sys_get_temp_dir() . '/sslscanner-test-' . bin2hex(random_bytes(4));
$store = new ScanStore($dir);
$id = str_repeat('ab', 16);
$store->writeProgress('alice', $id, ['status' => 'scanning', 'done' => 5]);
check('progress round-trips', ($store->readProgress('alice', $id)['done'] ?? null) === 5);
check('progress is per user', $store->readProgress('bob', $id) === null);
$store->requestCancel('alice', $id);
check('cancel flag set', $store->cancelRequested('alice', $id) && !$store->cancelRequested('bob', $id));
$store->clearProgress('alice', $id);
check('progress cleared', $store->readProgress('alice', $id) === null && !$store->cancelRequested('alice', $id));
check('rejects path-like ids', throws(fn () => $store->readProgress('alice', '../../etc/passwd')));
$store->saveResult('alice', ['results' => [1, 2]]);
check('results saved per user', $store->loadResult('alice') === ['results' => [1, 2]] && $store->loadResult('bob') === null);
echo "Saved runs\n";
$cert = ['host' => 'a.test', 'ip' => '10.0.0.1', 'port' => 443, 'sni' => 'a.test', 'ok' => true, 'error' => null,
    'cn' => 'a.test', 'sans' => ['a.test', 'www.a.test'], 'issuer' => 'Test CA', 'self_signed' => false,
    'issued' => $now - 86400, 'expires' => time() + 86400 * 10, 'days_left' => 10, 'serial' => '01', 'fingerprint' => 'ab'];
$miss = ['host' => '10.0.0.2', 'ip' => '10.0.0.2', 'port' => 443, 'sni' => null, 'ok' => false, 'error' => 'Connection timed out'];
$scan = ['at' => $now, 'targets' => "a.test\n10.0.0.2", 'ports' => '443', 'warnings' => [], 'elapsed' => 1.5, 'total' => 2, 'cancelled' => false, 'results' => [$cert, $miss]];

$runId = $store->saveRun('alice', $scan, '  Weekly   check ');
check('run saved with cleaned name', ($store->listRuns('alice')[0]['name'] ?? null) === 'Weekly check');
check('run list has counts', ($store->listRuns('alice')[0]['found'] ?? null) === 1 && $store->listRuns('alice')[0]['checks'] === 2);
check('runs are per user', $store->listRuns('bob') === [] && $store->loadRun('bob', $runId) === null);
$loaded = $store->loadRun('alice', $runId);
check('run loads with results', count($loaded['results']) === 2 && $loaded['results'][0]['sans'] === ['a.test', 'www.a.test'] && $loaded['saved_id'] === $runId);
$auto = $store->saveRun('alice', $scan, '');
check('blank name gets a default', str_starts_with($store->loadRun('alice', $auto)['name'], 'a.test, 10.0.0.2 — '));
check('rename works', $store->renameRun('alice', $runId, 'Renamed') && $store->loadRun('alice', $runId)['name'] === 'Renamed');
check('delete works', $store->deleteRun('alice', $runId) && $store->loadRun('alice', $runId) === null && count($store->listRuns('alice')) === 1);
check('bad run id rejected', $store->loadRun('alice', '../../x') === null && !$store->deleteRun('alice', 'zz'));

echo "Import validation\n";
$exported = json_decode(json_encode(ScanStore::exportRun($scan)), true);
check('export has format marker', $exported['format'] === 'php-ssl-scanner/run');
check('export round-trips', ScanStore::normalizeRun($exported)['results'][0]['cn'] === 'a.test');
check('rejects non-run JSON', throws(fn () => ScanStore::normalizeRun(['hello' => 'world'])));
check('rejects bad port', throws(fn () => ScanStore::normalizeRun(['results' => [['host' => 'x', 'port' => 70000]]])));
check('rejects cert without expiry', throws(fn () => ScanStore::normalizeRun(['results' => [['host' => 'x', 'port' => 443, 'ok' => true]]])));
$dirty = ScanStore::normalizeRun(['results' => [['host' => 'x', 'port' => '443', 'ok' => true, 'expires' => '2000000000', 'ip' => 'not-an-ip', 'sans' => ['a', ['nested']], 'evil' => 1]]]);
check('import coerces and drops junk', $dirty['results'][0]['port'] === 443 && $dirty['results'][0]['ip'] === null && $dirty['results'][0]['sans'] === ['a'] && !isset($dirty['results'][0]['evil']));

array_map('unlink', glob($dir . '/*'));
rmdir($dir);

echo $failures === 0 ? "\nAll tests passed.\n" : "\n{$failures} test(s) failed.\n";
exit($failures === 0 ? 0 : 1);
