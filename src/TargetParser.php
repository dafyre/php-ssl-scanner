<?php

declare(strict_types=1);

namespace SslScanner;

use InvalidArgumentException;

/**
 * Turns free-form user input into a list of scan targets and ports.
 *
 * Targets may be hostnames, IPv4/IPv6 addresses, or CIDR ranges, separated by
 * commas, spaces, or newlines. Ports may be single ports or ranges ("8000-8010").
 */
final class TargetParser
{
    /**
     * @param callable|null $resolver fn(string $hostname): string[] returning IP addresses.
     *                                Defaults to DNS lookup; injectable for tests.
     */
    public function __construct(
        private int $maxHosts = 1024,
        private int $maxPorts = 64,
        private $resolver = null,
    ) {
        $this->resolver ??= [self::class, 'resolve'];
    }

    /**
     * @return array{targets: list<array{label: string, ip: ?string, sni: ?string, error: ?string}>, errors: list<string>}
     */
    public function parseTargets(string $input): array
    {
        $targets = [];
        $errors = [];
        $tokens = preg_split('/[\s,;]+/', trim($input), -1, PREG_SPLIT_NO_EMPTY) ?: [];

        if ($tokens === []) {
            throw new InvalidArgumentException('Enter at least one hostname, IP address, or CIDR range.');
        }

        foreach ($tokens as $token) {
            if (str_contains($token, '/')) {
                foreach ($this->expandCidr($token) as $ip) {
                    $targets[] = ['label' => $ip, 'ip' => $ip, 'sni' => null, 'error' => null];
                }
            } elseif (filter_var($token, FILTER_VALIDATE_IP)) {
                $targets[] = ['label' => $token, 'ip' => $token, 'sni' => null, 'error' => null];
            } elseif (self::isHostname($token)) {
                $host = strtolower(rtrim($token, '.'));
                $ips = ($this->resolver)($host);
                if ($ips === []) {
                    $targets[] = ['label' => $host, 'ip' => null, 'sni' => $host, 'error' => 'DNS lookup failed'];
                }
                foreach ($ips as $ip) {
                    $targets[] = ['label' => $host, 'ip' => $ip, 'sni' => $host, 'error' => null];
                }
            } else {
                $errors[] = "Ignored \"{$token}\": not a valid hostname, IP address, or CIDR range.";
            }

            if (count($targets) > $this->maxHosts) {
                throw new InvalidArgumentException(
                    "Too many addresses: the limit is {$this->maxHosts} per scan."
                );
            }
        }

        return ['targets' => self::dedupe($targets), 'errors' => $errors];
    }

    /**
     * @return list<int>
     */
    public function parsePorts(string $input): array
    {
        $ports = [];
        $tokens = preg_split('/[\s,;]+/', trim($input), -1, PREG_SPLIT_NO_EMPTY) ?: [];

        if ($tokens === []) {
            throw new InvalidArgumentException('Enter at least one port.');
        }

        foreach ($tokens as $token) {
            if (preg_match('/^(\d{1,5})-(\d{1,5})$/', $token, $m)) {
                [$lo, $hi] = [(int) $m[1], (int) $m[2]];
                if ($lo > $hi) {
                    [$lo, $hi] = [$hi, $lo];
                }
                self::assertPort($lo, $token);
                self::assertPort($hi, $token);
                if ($hi - $lo + 1 > $this->maxPorts) {
                    throw new InvalidArgumentException("Port range {$token} is larger than the {$this->maxPorts}-port limit.");
                }
                for ($p = $lo; $p <= $hi; $p++) {
                    $ports[$p] = $p;
                }
            } elseif (preg_match('/^\d{1,5}$/', $token)) {
                $p = (int) $token;
                self::assertPort($p, $token);
                $ports[$p] = $p;
            } else {
                throw new InvalidArgumentException("\"{$token}\" is not a valid port or port range.");
            }

            if (count($ports) > $this->maxPorts) {
                throw new InvalidArgumentException("Too many ports: the limit is {$this->maxPorts} per scan.");
            }
        }

        sort($ports);
        return array_values($ports);
    }

    /**
     * Expands an IPv4 or IPv6 CIDR range into individual addresses. For IPv4
     * prefixes of /30 and shorter, the network and broadcast addresses are skipped.
     *
     * @return list<string>
     */
    public function expandCidr(string $cidr): array
    {
        if (!preg_match('#^([0-9a-fA-F:.]+)/(\d{1,3})$#', $cidr, $m) || !filter_var($m[1], FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException("\"{$cidr}\" is not a valid CIDR range.");
        }

        $packed = inet_pton($m[1]);
        $bits = strlen($packed) * 8;
        $prefix = (int) $m[2];
        if ($prefix > $bits) {
            throw new InvalidArgumentException("\"{$cidr}\" has an invalid prefix length.");
        }

        $hostBits = $bits - $prefix;
        if ($hostBits > 30 || (1 << $hostBits) > $this->maxHosts + 2) {
            throw new InvalidArgumentException(
                "\"{$cidr}\" contains more than {$this->maxHosts} addresses; use a smaller range."
            );
        }

        // Zero out the host bits to get the network address.
        $network = $packed;
        for ($i = 0; $i < strlen($network); $i++) {
            $keep = max(0, min(8, $prefix - $i * 8));
            $mask = $keep === 0 ? 0 : (0xFF << (8 - $keep)) & 0xFF;
            $network[$i] = chr(ord($network[$i]) & $mask);
        }

        $count = 1 << $hostBits;
        $skipEnds = $bits === 32 && $hostBits >= 2;
        $ips = [];
        $current = $network;
        for ($n = 0; $n < $count; $n++) {
            if (!($skipEnds && ($n === 0 || $n === $count - 1))) {
                $ips[] = inet_ntop($current);
            }
            $current = self::increment($current);
        }

        return $ips;
    }

    public static function isHostname(string $value): bool
    {
        $value = rtrim($value, '.');
        return strlen($value) <= 253
            && (bool) preg_match('/^(?=.*[a-zA-Z])([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/', $value);
    }

    /**
     * @return list<string>
     */
    public static function resolve(string $hostname): array
    {
        $ips = gethostbynamel($hostname) ?: [];
        if ($ips === []) {
            $records = @dns_get_record($hostname, DNS_AAAA) ?: [];
            $ips = array_column($records, 'ipv6');
        }
        return array_values(array_unique($ips));
    }

    private static function increment(string $packed): string
    {
        for ($i = strlen($packed) - 1; $i >= 0; $i--) {
            $byte = ord($packed[$i]) + 1;
            $packed[$i] = chr($byte & 0xFF);
            if ($byte <= 0xFF) {
                break;
            }
        }
        return $packed;
    }

    private static function assertPort(int $port, string $token): void
    {
        if ($port < 1 || $port > 65535) {
            throw new InvalidArgumentException("Port {$token} is outside 1-65535.");
        }
    }

    private static function dedupe(array $targets): array
    {
        $seen = [];
        $out = [];
        foreach ($targets as $t) {
            $key = $t['label'] . '|' . ($t['ip'] ?? '');
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $out[] = $t;
            }
        }
        return $out;
    }
}
