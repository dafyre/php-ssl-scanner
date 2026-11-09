<?php

declare(strict_types=1);

// Minimal dependency-free tests: php tests/run.php

require dirname(__DIR__) . '/src/bootstrap.php';

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

echo $failures === 0 ? "\nAll tests passed.\n" : "\n{$failures} test(s) failed.\n";
exit($failures === 0 ? 0 : 1);
