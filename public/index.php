<?php

declare(strict_types=1);

use SslScanner\ScanInputError;
use SslScanner\ScanJob;
use SslScanner\Scanner;
use SslScanner\ScanStore;

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

// Options for the filter dropdowns.
$portOptions = $results === null ? [] : array_values(array_unique(array_column($results, 'port')));
sort($portOptions);
$issuerOptions = array_count_values(array_map(static fn ($r) => (string) $r['issuer'], $found));
ksort($issuerOptions, SORT_NATURAL | SORT_FLAG_CASE);

// If this scan is (still) a saved run, show its name instead of the save form.
$savedName = null;
if ($scan !== null && isset($scan['saved_id'])) {
    foreach (scans()->listRuns($user) as $run) {
        if ($run['id'] === $scan['saved_id']) {
            $savedName = $run['name'];
        }
    }
}

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

    $job = ScanJob::fromConfig();
    try {
        $prepared = $job->prepare($targetsInput, $portsInput);
    } catch (ScanInputError $e) {
        $store->clearProgress($user, $scanId);
        $fail([$e->getMessage()], $e->warnings);
        return;
    }

    // Release the session lock so progress polling and other tabs work during a long scan.
    session_write_close();
    set_time_limit(0);
    // Keep going if the browser disconnects; the results are saved and shown on the next visit.
    ignore_user_abort(true);

    $started = microtime(true);
    $lastCancelCheck = 0.0;
    $scan = $job->run(
        $prepared,
        $targetsInput,
        $portsInput,
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

    $store->saveResult($user, $scan);
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

/** Lower-cased text the search box matches against. */
function search_text(array $r): string
{
    $text = implode(' ', array_filter([$r['host'], $r['ip'], $r['cn'], implode(' ', $r['sans']), $r['issuer'], $r['error']]));
    return function_exists('mb_strtolower') ? mb_strtolower($text) : strtolower($text);
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
  <?php if (isset($flash['notice'])): ?>
    <p class="notice ok" role="status"><?= h($flash['notice']) ?> <a href="runs.php">View saved runs</a></p>
  <?php endif; ?>
  <?php foreach ($warnings as $w): ?>
    <p class="warning"><?= h($w) ?></p>
  <?php endforeach; ?>

  <?php if ($results !== null): ?>
    <section class="results">
      <?php if (!empty($scan['cancelled'])): ?>
        <p class="warning">Scan cancelled after <?= count($results) ?> of <?= (int) $scan['total'] ?> checks. Showing partial results.</p>
      <?php endif; ?>

      <div class="run-header">
        <div class="run-title">
          <h2><?= $savedName !== null ? h($savedName) : 'Latest scan' ?></h2>
          <p class="muted">
            <?= count($results) ?> checks · <?= count($found) ?> certificates found ·
            scanned <span title="<?= h(gmdate('Y-m-d H:i:s', (int) $scan['at'])) ?> UTC"><?= h(gmdate('Y-m-d H:i', (int) $scan['at'])) ?> UTC</span>
            in <?= number_format((float) $scan['elapsed'], 1) ?>s
            <?php if ($savedName !== null): ?> · <span class="tag">saved run</span><?php endif; ?>
          </p>
        </div>
        <div class="run-actions">
          <?php if ($savedName === null): ?>
            <form method="post" action="runs.php" class="save-run">
              <?= csrf_field() ?>
              <input type="hidden" name="action" value="save">
              <input name="name" maxlength="120" aria-label="Name for this run" placeholder="<?= h(ScanStore::defaultName($scan)) ?>">
              <button type="submit" class="small">Save run</button>
            </form>
          <?php endif; ?>
          <a class="button secondary small" href="runs.php?download=current">Download JSON</a>
        </div>
      </div>

      <div class="filters card" id="filters">
        <div class="filter-row">
          <label class="grow">Search
            <input type="search" id="f-search" placeholder="Host, IP, name, SAN, or issuer" autocomplete="off">
          </label>
          <label>Port
            <select id="f-port">
              <option value="">All ports</option>
              <?php foreach ($portOptions as $p): ?><option value="<?= $p ?>"><?= $p ?></option><?php endforeach; ?>
            </select>
          </label>
          <label>Issuer
            <select id="f-issuer">
              <option value="">All issuers</option>
              <?php foreach ($issuerOptions as $iss => $n): ?><option value="<?= h($iss) ?>"><?= h($iss) ?> (<?= $n ?>)</option><?php endforeach; ?>
            </select>
          </label>
          <label>Self-signed
            <select id="f-self">
              <option value="">Any</option>
              <option value="1">Only self-signed</option>
              <option value="0">Exclude self-signed</option>
            </select>
          </label>
          <label>Expires within
            <span class="with-unit"><input type="number" id="f-within" min="0" step="1" inputmode="numeric" placeholder="any"> days</span>
          </label>
        </div>
        <div class="filter-row status-row">
          <div class="chips" role="group" aria-label="Status">
            <button type="button" class="chip expired" data-status="expired" aria-pressed="true">Expired <b><?= count($expired) ?></b></button>
            <button type="button" class="chip expiring" data-status="expiring" aria-pressed="true">Expiring ≤ <?= $warnDays ?> days <b><?= count($expiring) ?></b></button>
            <button type="button" class="chip valid" data-status="valid" aria-pressed="true">Valid <b><?= count($found) - count($expired) - count($expiring) ?></b></button>
            <button type="button" class="chip none" data-status="none" aria-pressed="false">No certificate <b><?= count($results) - count($found) ?></b></button>
          </div>
          <span class="spacer"></span>
          <span class="muted" id="f-count" aria-live="polite"></span>
          <button type="button" class="link" id="f-clear" hidden>Clear filters</button>
          <?php if ($results !== []): ?>
            <form method="post" action="export.php" id="export-form">
              <?= csrf_field() ?>
              <input type="hidden" name="rows" id="export-rows" value="">
              <input type="hidden" name="scan_at" value="<?= (int) $scan['at'] ?>">
              <button type="submit" class="secondary small" id="export-button">Download CSV</button>
            </form>
          <?php endif; ?>
        </div>
      </div>

      <p class="empty" id="no-matches" hidden>No results match these filters.</p>

      <div class="table-wrap">
        <table id="results">
          <colgroup>
            <col class="c-host"><col class="c-ip"><col class="c-port"><col class="c-cn"><col class="c-san">
            <col class="c-issuer"><col class="c-date"><col class="c-date"><col class="c-days">
          </colgroup>
          <thead>
            <tr>
              <th data-sort="text">Host</th>
              <th data-sort="ip">IP address</th>
              <th data-sort="num">Port</th>
              <th data-sort="text">Common name (CN)</th>
              <th class="wrap"><span class="nowrap">Subject alternative</span><br><span class="nowrap">names (SAN)</span></th>
              <th data-sort="text">Issuer</th>
              <th data-sort="num">Issued</th>
              <th data-sort="num">Expires</th>
              <th data-sort="num">Days left</th>
            </tr>
          </thead>
          <tbody>
          <?php foreach ($results as $i => $r): $cls = status_class($r, $warnDays); ?>
            <tr class="<?= $cls ?>"
                data-index="<?= $i ?>"
                data-status="<?= $cls ?>"
                data-port="<?= (int) $r['port'] ?>"
                data-issuer="<?= h($r['issuer'] ?? '') ?>"
                data-self="<?= $r['self_signed'] ? '1' : '0' ?>"
                data-days="<?= $r['ok'] ? (int) $r['days_left'] : '' ?>"
                data-search="<?= h(search_text($r)) ?>">
              <td class="host"><?= h($r['host']) ?></td>
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
                <td class="issuer"><?= h($r['issuer'] ?? '') ?><?= $r['self_signed'] ? ' <span class="tag">self-signed</span>' : '' ?></td>
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
