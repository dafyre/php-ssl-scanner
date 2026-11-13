<?php

declare(strict_types=1);

// Saved runs: list, save, load, rename, delete, download as JSON, and import from JSON.

use SslScanner\Scanner;
use SslScanner\ScanStore;

require dirname(__DIR__) . '/src/bootstrap.php';

send_security_headers();
$user = require_login();
$store = scans();

// ---- Download a run as JSON ---------------------------------------------------------

if (isset($_GET['download'])) {
    session_write_close();
    $id = (string) $_GET['download'];
    $scan = $id === 'current' ? $store->loadResult($user) : $store->loadRun($user, $id);
    if ($scan === null) {
        http_response_code(404);
        exit('That run no longer exists.');
    }
    $slug = trim((string) preg_replace('/[^A-Za-z0-9._-]+/', '-', (string) ($scan['name'] ?? '')), '-');
    $file = 'ssl-scan-' . gmdate('Ymd-His', (int) $scan['at']) . ($slug !== '' ? '-' . substr($slug, 0, 60) : '') . '.json';
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $file . '"');
    echo json_encode(ScanStore::exportRun($scan), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

// ---- Actions ------------------------------------------------------------------------

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string) ($_POST['action'] ?? '');
    $id = (string) ($_POST['id'] ?? '');
    $back = 'runs.php';

    if (!csrf_valid()) {
        flash(['errors' => ['Your session expired. Please try again.']]);
    } else {
        switch ($action) {
            case 'save':
                $current = $store->loadResult($user);
                if ($current === null) {
                    flash(['errors' => ['There is no scan to save yet.']]);
                    break;
                }
                $newId = $store->saveRun($user, $current, (string) ($_POST['name'] ?? ''));
                $run = $store->loadRun($user, $newId);
                $store->saveResult($user, $run); // the on-screen scan is now this saved run
                flash(['notice' => 'Saved as “' . $run['name'] . '”.']);
                $back = 'index.php';
                break;

            case 'load':
                $run = $store->loadRun($user, $id);
                if ($run === null) {
                    flash(['errors' => ['That run no longer exists.']]);
                    break;
                }
                $store->saveResult($user, $run);
                $back = 'index.php';
                break;

            case 'rename':
                $store->renameRun($user, $id, (string) ($_POST['name'] ?? ''))
                    ? flash(['notice' => 'Run renamed.'])
                    : flash(['errors' => ['Could not rename that run. Names can’t be blank.']]);
                break;

            case 'delete':
                $store->deleteRun($user, $id)
                    ? flash(['notice' => 'Run deleted.'])
                    : flash(['errors' => ['That run no longer exists.']]);
                break;

            case 'import':
                try {
                    $newId = $store->saveRun($user, read_upload(), (string) ($_POST['name'] ?? ''));
                    flash(['notice' => 'Imported “' . $store->loadRun($user, $newId)['name'] . '”.']);
                } catch (InvalidArgumentException $e) {
                    flash(['errors' => ['Import failed: ' . $e->getMessage()]]);
                }
                break;

            default:
                flash(['errors' => ['Unknown action.']]);
        }
    }

    header('Location: ' . $back, true, 303);
    exit;
}

/** @throws InvalidArgumentException */
function read_upload(): array
{
    $file = $_FILES['file'] ?? null;
    if (!is_array($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        throw new InvalidArgumentException('Choose a .json file to import.');
    }
    if ($file['error'] === UPLOAD_ERR_INI_SIZE || $file['error'] === UPLOAD_ERR_FORM_SIZE || $file['size'] > 50 * 1024 * 1024) {
        throw new InvalidArgumentException('The file is too large.');
    }
    if ($file['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'])) {
        throw new InvalidArgumentException('The upload did not complete.');
    }
    $data = json_decode((string) file_get_contents($file['tmp_name']), true);
    if (!is_array($data)) {
        throw new InvalidArgumentException('The file is not valid JSON.');
    }
    return $data;
}

// ---- List page ----------------------------------------------------------------------

function run_name_key(string $name): string
{
    $name = trim((string) preg_replace('/\s+/u', ' ', $name));
    return function_exists('mb_strtolower') ? mb_strtolower($name) : strtolower($name);
}

/** The user whose crontab should run scheduled scans: the web server's user, never root. */
function web_user_for_cron(): string
{
    $u = process_user();
    return $u === null || $u === 'root' ? 'www-data' : $u;
}

/** A ready-to-paste crontab line that re-runs this saved run with bin/run-saved.php. */
function cron_line(array $run, array $nameCounts): string
{
    $script = APP_ROOT . '/bin/run-saved.php';
    $which = ($nameCounts[run_name_key($run['name'])] ?? 0) > 1
        ? '--id=' . $run['id']
        : escapeshellarg($run['name']);
    return '0 7 * * *  php ' . escapeshellarg($script) . ' --quiet ' . $which;
}

$flash = take_flash();
$runs = $store->listRuns($user);
$nameCounts = array_count_values(array_map(static fn ($r) => run_name_key($r['name']), $runs));
$currentId = $store->loadResult($user)['saved_id'] ?? null;
$warnDays = (int) config('warn_days');

$title = 'Saved runs';
require APP_ROOT . '/templates/header.php';
?>
<main>
  <div class="page-head">
    <h1>Saved runs</h1>
    <p class="muted">Save a scan from the results page to keep it here. Loading a run shows it on the scan page, where you can filter it, export it, or re-run the same targets.</p>
  </div>

  <?php foreach ($flash['errors'] ?? [] as $e): ?>
    <p class="error" role="alert"><?= h($e) ?></p>
  <?php endforeach; ?>
  <?php if (isset($flash['notice'])): ?>
    <p class="notice ok" role="status"><?= h($flash['notice']) ?></p>
  <?php endif; ?>

  <?php if ($runs === []): ?>
    <p class="empty">No saved runs yet. Run a scan, then use <strong>Save run</strong> above the results.</p>
  <?php else: ?>
    <div class="table-wrap">
      <table class="runs">
        <thead>
          <tr>
            <th>Name</th>
            <th>Scanned</th>
            <th>Targets</th>
            <th>Ports</th>
            <th class="num">Checks</th>
            <th class="num">Certs</th>
            <th class="num">Expired</th>
            <th class="num">Expiring</th>
            <th><span class="visually-hidden">Actions</span></th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($runs as $run):
            $expiredNow = $expiringNow = 0;
            foreach ($run['expires'] as $exp) {
                $d = Scanner::daysLeft((int) $exp);
                $d < 0 ? $expiredNow++ : ($d <= $warnDays ? $expiringNow++ : null);
            }
            ?>
          <tr<?= $run['id'] === $currentId ? ' class="current"' : '' ?>>
            <td class="run-name">
              <strong><?= h($run['name']) ?></strong>
              <?php if ($run['id'] === $currentId): ?> <span class="tag">on scan page</span><?php endif; ?>
              <?php if ($run['cancelled']): ?> <span class="tag">partial</span><?php endif; ?>
              <div class="run-tools">
              <details class="rename">
                <summary>Rename</summary>
                <form method="post">
                  <?= csrf_field() ?>
                  <input type="hidden" name="action" value="rename">
                  <input type="hidden" name="id" value="<?= h($run['id']) ?>">
                  <input name="name" value="<?= h($run['name']) ?>" maxlength="120" required aria-label="New name">
                  <button type="submit" class="small">Save</button>
                </form>
              </details>
              <button type="button" class="link toggle-schedule" aria-expanded="false" aria-controls="schedule-<?= h($run['id']) ?>">Schedule</button>
              </div>
            </td>
            <td>
              <time title="Saved <?= h(gmdate('Y-m-d H:i', (int) $run['saved_at'])) ?> UTC"><?= h(gmdate('Y-m-d H:i', (int) $run['at'])) ?></time>
              <?php if (($run['updated_via'] ?? null) === 'schedule'): ?><br><span class="tag" title="Last updated by bin/run-saved.php">by schedule</span><?php endif; ?>
            </td>
            <td class="targets-cell" title="<?= h($run['targets']) ?>"><?= h(preg_replace('/\s+/', ' ', $run['targets'])) ?></td>
            <td class="nowrap"><?= h($run['ports']) ?></td>
            <td class="num"><?= (int) $run['checks'] ?></td>
            <td class="num"><?= (int) $run['found'] ?></td>
            <td class="num<?= $expiredNow ? ' expired-text' : '' ?>"><?= $expiredNow ?></td>
            <td class="num<?= $expiringNow ? ' expiring-text' : '' ?>"><?= $expiringNow ?></td>
            <td class="actions">
              <form method="post">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="load">
                <input type="hidden" name="id" value="<?= h($run['id']) ?>">
                <button type="submit" class="small">Load</button>
              </form>
              <a class="button secondary small" href="runs.php?download=<?= h($run['id']) ?>">JSON</a>
              <form method="post" data-confirm="Delete “<?= h($run['name']) ?>”? This can’t be undone.">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="id" value="<?= h($run['id']) ?>">
                <button type="submit" class="link danger">Delete</button>
              </form>
            </td>
          </tr>
          <tr class="schedule-row" id="schedule-<?= h($run['id']) ?>" hidden>
            <td colspan="9">
                <?php $cron = cron_line($run, $nameCounts); ?>
                <div class="schedule-body">
                  <p>To re-scan this run automatically every day at 07:00, add this line to the web server user’s crontab
                    (<code>sudo crontab -u <?= h(web_user_for_cron()) ?> -e</code>):</p>
                  <div class="copy-row">
                    <code class="cron" id="cron-<?= h($run['id']) ?>"><?= h($cron) ?></code>
                    <button type="button" class="secondary small" data-copy="cron-<?= h($run['id']) ?>">Copy</button>
                  </div>
                  <p class="muted">Each run updates this saved run and, with <code>--quiet</code>, prints a report only when a certificate has expired or expires within <?= (int) config('warn_days') ?> days. Cron emails that report to the crontab’s <code>MAILTO</code> address. Drop <code>--quiet</code> to get a report every time.
                    <?php if (($nameCounts[run_name_key($run['name'])] ?? 0) > 1): ?>Another run has the same name, so this line uses the run’s id.<?php endif; ?></p>
                </div>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  <?php endif; ?>

  <form method="post" enctype="multipart/form-data" class="card import-form">
    <h2>Import a run</h2>
    <p class="muted">Upload a <code>.json</code> file downloaded from this app, for example from another server or a backup.</p>
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="import">
    <div class="import-fields">
      <label>File <input type="file" name="file" accept=".json,application/json" required></label>
      <label>Name <small>(optional; defaults to the name in the file)</small>
        <input name="name" maxlength="120">
      </label>
      <button type="submit">Import</button>
    </div>
  </form>
</main>
<?php require APP_ROOT . '/templates/footer.php'; ?>
