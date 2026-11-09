<?php

declare(strict_types=1);

use SslScanner\Scanner;
use SslScanner\ScanStore;
use SslScanner\TargetParser;

require dirname(__DIR__) . '/src/bootstrap.php';

send_security_headers();

$user = require_login();
$warnDays = (int) config('warn_days');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    handle_scan($user);
    // Post/redirect/get: the result page is always rendered by a GET, so refreshing it
    // never re-runs a scan.
    if (is_ajax()) {
        header('Content-Type: application/json');
        echo json_encode(['redirect' => 'index.php']);
    } else {
        header('Location: index.php', true, 303);
    }
    exit;
}

$flash = take_flash();
$last = scans()->loadResult($user);
$errors = $flash['errors'] ?? [];
$warnings = $flash['warnings'] ?? ($last['warnings'] ?? []);
$targetsInput = $flash['targets'] ?? ($last['targets'] ?? '');
$portsInput = $flash['ports'] ?? ($last['ports'] ?? (string) config('default_ports'));

// Show the last scan unless this page load is reporting a failed submission.
$scan = isset($flash['errors']) ? null : $last;
$results = $scan['results'] ?? null;
if ($results !== null) {
    // Days-left was a snapshot at scan time; recompute it so old results stay accurate.
    foreach ($results as &$r) {
        if ($r['ok']) {
            $r['days_left'] = Scanner::daysLeft((int) $r['expires']);
        }
    }
    unset($r);
}

$found = $results === null ? [] : array_filter($results, static fn ($r) => $r['ok']);
$expired = array_filter($found, static fn ($r) => $r['days_left'] < 0);
$expiring = array_filter($found, static fn ($r) => $r['days_left'] >= 0 && $r['days_left'] <= $warnDays);

/**
 * Validates the form, runs the scan while publishing progress, and saves the results.
 * Problems are flashed to the session for the next page load.
 */
function handle_scan(string $user): void
{
    $targetsInput = (string) ($_POST['targets'] ?? '');
    $portsInput = (string) ($_POST['ports'] ?? '');
    $scanId = (string) ($_POST['scan_id'] ?? '');
    $scanId = ScanStore::isValidId($scanId) ? $scanId : bin2hex(random_bytes(16));
    $fail = static function (array $errors, array $warnings = []) use ($targetsInput, $portsInput): void {
        flash(['errors' => $errors, 'warnings' => $warnings, 'targets' => $targetsInput, 'ports' => $portsInput]);
    };

    if (!csrf_valid()) {
        $fail(['Your session expired. Please submit the form again.']);
        return;
    }

    $store = scans();
    $store->cleanup();
    $store->writeProgress($user, $scanId, ['status' => 'preparing']);

    try {
        $parser = new TargetParser((int) config('max_hosts'), (int) config('max_ports'));
        $ports = $parser->parsePorts($portsInput);
        $parsed = $parser->parseTargets($targetsInput);
    } catch (InvalidArgumentException $e) {
        $store->clearProgress($user, $scanId);
        $fail([$e->getMessage()]);
        return;
    }

    $checks = count($parsed['targets']) * count($ports);
    if ($parsed['targets'] === []) {
        $store->clearProgress($user, $scanId);
        $fail(['No valid targets to scan.'], $parsed['errors']);
        return;
    }
    if ($checks > (int) config('max_checks')) {
        $store->clearProgress($user, $scanId);
        $fail(["That would be {$checks} host/port checks; the limit is " . config('max_checks') . '. Narrow the range or the port list.'], $parsed['errors']);
        return;
    }

    // Release the session lock so progress polling and other tabs work during a long scan.
    session_write_close();
    set_time_limit(0);
    // Keep going if the browser disconnects; the results are saved and shown on the next visit.
    ignore_user_abort(true);

    $started = microtime(true);
    $lastCancelCheck = 0.0;
    $scanner = new Scanner((float) config('timeout'), (int) config('concurrency'));
    $results = $scanner->scan(
        $parsed['targets'],
        $ports,
        static function (int $done, int $total, int $found) use ($store, $user, $scanId, $started, &$lastCancelCheck): bool {
            $store->writeProgress($user, $scanId, [
                'status' => 'scanning',
                'done' => $done,
                'total' => $total,
                'found' => $found,
                'elapsed' => microtime(true) - $started,
            ]);
            if (microtime(true) - $lastCancelCheck >= 0.5) {
                $lastCancelCheck = microtime(true);
                return !$store->cancelRequested($user, $scanId);
            }
            return true;
        },
    );

    usort($results, static function (array $a, array $b): int {
        if ($a['ok'] !== $b['ok']) {
            return $a['ok'] ? -1 : 1;
        }
        if ($a['ok'] && $a['expires'] !== $b['expires']) {
            return $a['expires'] <=> $b['expires'];
        }
        return [$a['host'], inet_pton((string) $a['ip']) ?: '', $a['port']]
            <=> [$b['host'], inet_pton((string) $b['ip']) ?: '', $b['port']];
    });

    $store->saveResult($user, [
        'at' => time(),
        'targets' => $targetsInput,
        'ports' => $portsInput,
        'warnings' => $parsed['errors'],
        'elapsed' => microtime(true) - $started,
        'total' => $checks,
        'cancelled' => $scanner->wasCancelled(),
        'results' => $results,
    ]);
    $store->clearProgress($user, $scanId);
}

function status_class(array $r, int $warnDays): string
{
    if (!$r['ok']) {
        return 'none';
    }
    if ($r['days_left'] < 0) {
        return 'expired';
    }
    return $r['days_left'] <= $warnDays ? 'expiring' : 'valid';
}

function fmt_date(?int $ts): string
{
    return $ts ? '<time datetime="' . gmdate('c', $ts) . '" title="' . gmdate('Y-m-d H:i:s', $ts) . ' UTC">' . gmdate('Y-m-d', $ts) . '</time>' : '';
}

$title = 'Scan';
require APP_ROOT . '/templates/header.php';
?>
<main>
  <form method="post" class="card scan-form" id="scan-form">
    <?= csrf_field() ?>
    <div class="fields">
      <label class="targets">Hosts, IP addresses, or CIDR ranges
        <textarea name="targets" rows="4" required placeholder="example.com&#10;10.0.0.15&#10;192.168.1.0/24"><?= h($targetsInput) ?></textarea>
        <small>Separate with commas, spaces, or new lines. Up to <?= (int) config('max_hosts') ?> addresses per scan.</small>
      </label>
      <label class="ports">Ports
        <input name="ports" value="<?= h($portsInput) ?>" required placeholder="443, 8443, 9000-9010">
        <small>Single ports or ranges, comma-separated.</small>
      </label>
    </div>
    <button type="submit" id="scan-button">Scan</button>

    <div class="scan-status" id="scan-status" hidden>
      <div class="status-line">
        <span id="status-text" aria-live="polite">Preparing scan…</span>
        <button type="button" class="secondary small" id="cancel-button">Cancel</button>
      </div>
      <div class="bar" id="progress-bar" role="progressbar" aria-label="Scan progress" aria-valuemin="0" aria-valuemax="100">
        <div class="fill" id="progress-fill"></div>
      </div>
      <div class="status-detail" id="status-detail"></div>
    </div>
  </form>

  <p class="error" role="alert" id="scan-error" hidden></p>

  <?php foreach ($errors as $e): ?>
    <p class="error" role="alert"><?= h($e) ?></p>
  <?php endforeach; ?>
  <?php foreach ($warnings as $w): ?>
    <p class="warning"><?= h($w) ?></p>
  <?php endforeach; ?>

  <?php if ($results !== null): ?>
    <section class="results">
      <?php if (!empty($scan['cancelled'])): ?>
        <p class="warning">Scan cancelled after <?= count($results) ?> of <?= (int) $scan['total'] ?> checks. Showing partial results.</p>
      <?php endif; ?>
      <div class="summary">
        <span><strong><?= count($results) ?></strong> checks</span>
        <span><strong><?= count($found) ?></strong> certificates found</span>
        <span class="expired"><strong><?= count($expired) ?></strong> expired</span>
        <span class="expiring"><strong><?= count($expiring) ?></strong> expiring within <?= $warnDays ?> days</span>
        <span class="muted" title="<?= h(gmdate('Y-m-d H:i:s', (int) $scan['at'])) ?> UTC">
          Scanned <?= h(gmdate('Y-m-d H:i', (int) $scan['at'])) ?> UTC in <?= number_format((float) $scan['elapsed'], 1) ?>s
        </span>
        <span class="spacer"></span>
        <label class="toggle"><input type="checkbox" id="show-failures"> Show addresses with no certificate (<?= count($results) - count($found) ?>)</label>
        <?php if ($results !== []): ?>
          <a class="button secondary" href="export.php">Download CSV</a>
        <?php endif; ?>
      </div>

      <?php if ($found === []): ?>
        <p class="empty" id="empty-note">No certificates were found. Tick “Show addresses with no certificate” to see why each check failed.</p>
      <?php endif; ?>

      <div class="table-wrap">
        <table id="results" class="hide-failures">
          <thead>
            <tr>
              <th data-sort="text">Host</th>
              <th data-sort="ip">IP address</th>
              <th data-sort="num">Port</th>
              <th data-sort="text">Common name (CN)</th>
              <th>Subject alternative names (SAN)</th>
              <th data-sort="text">Issuer</th>
              <th data-sort="num">Issued</th>
              <th data-sort="num">Expires</th>
              <th data-sort="num">Days left</th>
            </tr>
          </thead>
          <tbody>
          <?php foreach ($results as $r): $cls = status_class($r, $warnDays); ?>
            <tr class="<?= $cls ?>">
              <td><?= h($r['host']) ?></td>
              <td data-value="<?= h($r['ip'] ?? '') ?>"><?= h($r['ip'] ?? '—') ?></td>
              <td data-value="<?= (int) $r['port'] ?>"><?= (int) $r['port'] ?></td>
              <?php if ($r['ok']): ?>
                <td class="cn"><?= h($r['cn'] ?? '(none)') ?></td>
                <td class="sans">
                  <?php if ($r['sans'] === []): ?>
                    <span class="muted">none</span>
                  <?php else: ?>
                    <ul><?php foreach ($r['sans'] as $san): ?><li><?= h($san) ?></li><?php endforeach; ?></ul>
                  <?php endif; ?>
                </td>
                <td><?= h($r['issuer'] ?? '') ?><?= $r['self_signed'] ? ' <span class="tag">self-signed</span>' : '' ?></td>
                <td data-value="<?= (int) $r['issued'] ?>"><?= fmt_date($r['issued']) ?></td>
                <td data-value="<?= (int) $r['expires'] ?>"><?= fmt_date($r['expires']) ?></td>
                <td data-value="<?= (int) $r['days_left'] ?>" class="days">
                  <?= $r['days_left'] < 0 ? 'Expired ' . abs($r['days_left']) . 'd ago' : (int) $r['days_left'] ?>
                </td>
              <?php else: ?>
                <td colspan="6" class="muted" data-value=""><?= h($r['error']) ?></td>
              <?php endif; ?>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </section>
  <?php endif; ?>
</main>
<?php require APP_ROOT . '/templates/footer.php'; ?>
