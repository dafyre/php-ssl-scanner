<?php

declare(strict_types=1);

namespace SslScanner;

/**
 * Plain-text report of a scan for cron email: expired and expiring certificates, plus
 * what changed since the previous run. ASCII only so it reads well in any mail client.
 */
final class Report
{
    public const OK = 0;
    public const EXPIRING = 1;
    public const EXPIRED = 2;
    public const ERROR = 3;

    public function __construct(private int $warnDays)
    {
    }

    /** Nagios-style exit status: 2 if anything has expired, 1 if anything is expiring, else 0. */
    public function status(array $scan, ?int $now = null): int
    {
        [$expired, $expiring] = $this->classify($scan['results'], $now);
        return $expired !== [] ? self::EXPIRED : ($expiring !== [] ? self::EXPIRING : self::OK);
    }

    /**
     * @param array|null $previous the run's results before this scan, for the "changes" section
     */
    public function render(string $name, array $scan, ?array $previous = null, bool $listAll = false, ?int $now = null): string
    {
        $now ??= time();
        [$expired, $expiring, $valid] = $this->classify($scan['results'], $now);
        $found = count($expired) + count($expiring) + count($valid);
        $none = count($scan['results']) - $found;

        $out = [];
        $out[] = "SSL certificate scan: {$name}";
        $out[] = sprintf(
            'Scanned %s UTC - %d checks in %.1fs%s',
            gmdate('Y-m-d H:i', (int) $scan['at']),
            count($scan['results']),
            (float) $scan['elapsed'],
            !empty($scan['cancelled']) ? ' - INCOMPLETE (scan was cancelled)' : '',
        );
        $out[] = sprintf(
            '%d certificate%s: %d expired, %d expiring within %d days, %d valid. %d check%s found no certificate.',
            $found, $found === 1 ? '' : 's', count($expired), count($expiring), $this->warnDays, count($valid),
            $none, $none === 1 ? '' : 's',
        );

        foreach ($scan['warnings'] ?? [] as $w) {
            $out[] = 'Warning: ' . $w;
        }

        $sections = [['EXPIRED', $expired], ["EXPIRING WITHIN {$this->warnDays} DAYS", $expiring]];
        if ($listAll) {
            $sections[] = ['VALID', $valid];
        }
        foreach ($sections as [$title, $rows]) {
            if ($rows !== []) {
                $out[] = '';
                $out[] = $title . ' (' . count($rows) . ')';
                $out = array_merge($out, $this->table($rows, $now));
            }
        }

        if ($previous !== null) {
            $out = array_merge($out, $this->changes($previous, $scan, $now));
        }

        if ($expired === [] && $expiring === []) {
            $out[] = '';
            $out[] = "Nothing has expired or expires within {$this->warnDays} days.";
        }

        return implode(PHP_EOL, $out) . PHP_EOL;
    }

    /** @return array{0: list<array>, 1: list<array>, 2: list<array>} expired, expiring, valid */
    private function classify(array $results, ?int $now): array
    {
        $groups = [[], [], []];
        foreach ($results as $r) {
            if (!$r['ok']) {
                continue;
            }
            $days = Scanner::daysLeft((int) $r['expires'], $now);
            $groups[$days < 0 ? 0 : ($days <= $this->warnDays ? 1 : 2)][] = $r + ['days_now' => $days];
        }
        return $groups;
    }

    /** @return list<string> */
    private function table(array $rows, int $now): array
    {
        usort($rows, static fn ($a, $b) => $a['expires'] <=> $b['expires']);
        $lines = [['When', 'Expires', 'Common name', 'Host:port', 'Issuer']];
        foreach ($rows as $r) {
            $lines[] = [
                self::when($r['days_now']),
                gmdate('Y-m-d', (int) $r['expires']),
                (string) ($r['cn'] ?? '(none)'),
                self::where($r),
                ($r['issuer'] ?? '') . ($r['self_signed'] ? ' (self-signed)' : ''),
            ];
        }
        return self::columns($lines);
    }

    /** Certificates renewed, newly found, or no longer answering since the previous run. */
    private function changes(array $previous, array $scan, int $now): array
    {
        $key = static fn (array $r): string => $r['host'] . '|' . $r['ip'] . '|' . $r['port'];
        $before = [];
        foreach ($previous['results'] ?? [] as $r) {
            if ($r['ok']) {
                $before[$key($r)] = $r;
            }
        }
        $after = [];
        foreach ($scan['results'] as $r) {
            if ($r['ok']) {
                $after[$key($r)] = $r;
            }
        }

        $renewed = $new = $gone = [];
        foreach ($after as $k => $r) {
            if (!isset($before[$k])) {
                $new[] = [self::where($r), (string) $r['cn'], 'expires ' . gmdate('Y-m-d', (int) $r['expires'])];
            } elseif (($before[$k]['fingerprint'] ?? null) !== ($r['fingerprint'] ?? null)) {
                $renewed[] = [
                    self::where($r),
                    (string) $r['cn'],
                    'expiry ' . gmdate('Y-m-d', (int) $before[$k]['expires']) . ' -> ' . gmdate('Y-m-d', (int) $r['expires']),
                ];
            }
        }
        foreach ($before as $k => $r) {
            if (!isset($after[$k])) {
                $gone[] = [self::where($r), (string) $r['cn'], 'had expiry ' . gmdate('Y-m-d', (int) $r['expires'])];
            }
        }

        $since = isset($previous['at']) ? ' (' . gmdate('Y-m-d H:i', (int) $previous['at']) . ' UTC)' : '';
        $out = ['', "CHANGES SINCE LAST RUN{$since}"];
        if ($renewed === [] && $new === [] && $gone === []) {
            $out[] = '  No changes.';
            return $out;
        }
        foreach ([['Replaced or renewed', $renewed], ['New certificates', $new], ['No longer answering', $gone]] as [$title, $rows]) {
            if ($rows !== []) {
                $out[] = "  {$title} (" . count($rows) . '):';
                foreach (self::columns($rows, '    ') as $line) {
                    $out[] = $line;
                }
            }
        }
        return $out;
    }

    private static function when(int $days): string
    {
        return match (true) {
            $days < -1 => abs($days) . ' days ago',
            $days === -1 => '1 day ago',
            $days === 0 => 'today',
            $days === 1 => 'in 1 day',
            default => "in {$days} days",
        };
    }

    private static function where(array $r): string
    {
        $ip = (string) ($r['ip'] ?? '');
        $hostPort = (str_contains($r['host'], ':') ? "[{$r['host']}]" : $r['host']) . ':' . $r['port'];
        return $ip !== '' && $ip !== $r['host'] ? "{$hostPort} ({$ip})" : $hostPort;
    }

    /**
     * @param list<list<string>> $rows
     * @return list<string>
     */
    private static function columns(array $rows, string $indent = '  '): array
    {
        $widths = [];
        foreach ($rows as $row) {
            foreach ($row as $i => $cell) {
                $widths[$i] = max($widths[$i] ?? 0, strlen($cell));
            }
        }
        $lines = [];
        foreach ($rows as $row) {
            $cells = [];
            foreach ($row as $i => $cell) {
                $cells[] = $i === count($row) - 1 ? $cell : str_pad($cell, $widths[$i]);
            }
            $lines[] = rtrim($indent . implode('  ', $cells));
        }
        return $lines;
    }
}
