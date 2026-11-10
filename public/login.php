<?php

declare(strict_types=1);

use SslScanner\LoginThrottle;

require dirname(__DIR__) . '/src/bootstrap.php';

send_security_headers();

if (current_user() !== null) {
    header('Location: index.php');
    exit;
}

$error = null;
$username = '';
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$throttle = new LoginThrottle(
    config('data_dir') . '/login_throttle.json',
    (int) config('login_max_attempts'),
    (int) config('login_lockout_window'),
);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    if (!csrf_valid()) {
        $error = 'Your session expired. Please try again.';
    } elseif (($wait = $throttle->lockedFor($ip)) > 0) {
        $error = 'Too many failed attempts. Try again in ' . (int) ceil($wait / 60) . ' minute(s).';
    } elseif ($username !== '' && users()->verify($username, $password)) {
        $throttle->clear($ip);
        login($username);
        header('Location: index.php');
        exit;
    } else {
        $throttle->recordFailure($ip);
        $error = 'Invalid username or password.';
    }
}

$problems = storage_problems();
$noUsers = $problems === [] && users()->list() === [];
$cliUser = process_user();
$userCommand = ($cliUser !== null && $cliUser !== 'root' ? "sudo -u {$cliUser} " : '') . 'php bin/user.php add <username>';
$title = 'Sign in';
require APP_ROOT . '/templates/header.php';
?>
<main class="login">
  <form method="post" class="card" autocomplete="on">
    <h1><?= h(config('app_name')) ?></h1>
    <?php if ($problems !== []): ?>
      <div class="error setup" role="alert">
        <strong>Setup problem:</strong>
        <?php foreach ($problems as $p): ?><p><?= h($p) ?></p><?php endforeach; ?>
        <p>Signing in won’t work until this is fixed. On the server, run:</p>
        <code><?= h(storage_fix_command()) ?></code>
      </div>
    <?php elseif ($noUsers): ?>
      <p class="notice">No users exist yet. On the server, from the app folder, run<br><code><?= h($userCommand) ?></code></p>
    <?php endif; ?>
    <?php if ($error && $problems === []): ?>
      <p class="error" role="alert"><?= h($error) ?></p>
    <?php endif; ?>
    <?= csrf_field() ?>
    <label>Username
      <input name="username" value="<?= h($username) ?>" autocomplete="username" required autofocus>
    </label>
    <label>Password
      <input name="password" type="password" autocomplete="current-password" required>
    </label>
    <button type="submit">Sign in</button>
  </form>
</main>
<?php require APP_ROOT . '/templates/footer.php'; ?>
