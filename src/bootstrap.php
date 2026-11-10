<?php

declare(strict_types=1);

use SslScanner\ScanStore;
use SslScanner\UserStore;

define('APP_ROOT', dirname(__DIR__));

spl_autoload_register(static function (string $class): void {
    $prefix = 'SslScanner\\';
    if (str_starts_with($class, $prefix)) {
        $file = APP_ROOT . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});

function config(?string $key = null): mixed
{
    static $config = null;
    if ($config === null) {
        $defaults = [
            'app_name' => 'SSL Certificate Scanner',
            'data_dir' => APP_ROOT . '/data',
            'timeout' => 4.0,
            'concurrency' => 64,
            'max_hosts' => 1024,
            'max_ports' => 64,
            'max_checks' => 8192,
            'warn_days' => 30,
            'session_idle_timeout' => 1800,
            'login_max_attempts' => 5,
            'login_lockout_window' => 900,
            'default_ports' => '443',
        ];
        $file = APP_ROOT . '/config/config.php';
        $config = array_merge($defaults, is_file($file) ? (array) require $file : []);
    }
    return $key === null ? $config : ($config[$key] ?? null);
}

function users(): UserStore
{
    static $store = null;
    return $store ??= new UserStore(config('data_dir') . '/users.json');
}

function scans(): ScanStore
{
    static $store = null;
    return $store ??= new ScanStore(config('data_dir') . '/scans');
}

/** Name of the OS user PHP is running as (e.g. www-data), or null if it can't be determined. */
function process_user(): ?string
{
    if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
        return posix_getpwuid(posix_geteuid())['name'] ?? null;
    }
    return null;
}

/**
 * Checks that PHP can read and write the data directory. Returns human-readable problems,
 * most commonly caused by running bin/user.php as root so Apache/PHP-FPM can't read the files.
 *
 * @return list<string>
 */
function storage_problems(): array
{
    static $problems = null;
    if ($problems !== null) {
        return $problems;
    }

    $problems = [];
    $dir = rtrim((string) config('data_dir'), '/');
    $as = process_user();
    $who = $as !== null ? "the web server (running as “{$as}”)" : 'the web server';
    $rel = static fn (string $path): string => str_starts_with($path, APP_ROOT . '/') ? substr($path, strlen(APP_ROOT) + 1) : basename($path);

    if (!file_exists($dir)) {
        if (!is_writable(dirname($dir))) {
            $problems[] = "The data folder ({$rel($dir)}/) doesn't exist and {$who} can't create it.";
        }
    } elseif (!is_dir($dir) || !is_readable($dir) || !is_writable($dir) || !is_executable($dir)) {
        $problems[] = ucfirst($who) . " can't read and write the data folder ({$rel($dir)}/).";
    } else {
        foreach (['users.json', 'login_throttle.json', 'scans'] as $name) {
            $path = "{$dir}/{$name}";
            if (file_exists($path) && (!is_readable($path) || !is_writable($path))) {
                $problems[] = ucfirst($who) . " can't read and write {$rel($path)}.";
            }
        }
    }

    foreach ($problems as $p) {
        error_log('[ssl-scanner] ' . $p);
    }
    return $problems;
}

/** The command that fixes storage_problems(), for showing to an admin. */
function storage_fix_command(): string
{
    $owner = process_user() ?? 'www-data';
    $group = $owner;
    if (function_exists('posix_getegid') && function_exists('posix_getgrgid')) {
        $group = posix_getgrgid(posix_getegid())['name'] ?? $owner;
    }
    $dir = realpath((string) config('data_dir')) ?: (string) config('data_dir');
    return "sudo chown -R {$owner}:{$group} {$dir}";
}

/** True when the request came from the page's JavaScript rather than a plain form post. */
function is_ajax(): bool
{
    return ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'fetch';
}

/** Escape for HTML output. */
function h(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * @param bool $readOnly Read the session and release it immediately, without writing it
 *                       back. Used by the progress poller so it can never overwrite
 *                       changes made by the long-running scan request.
 */
function start_session(bool $readOnly = false): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $https = ($_SERVER['HTTPS'] ?? '') !== '' && $_SERVER['HTTPS'] !== 'off';
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('sslscanner');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $https,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start($readOnly ? ['read_and_close' => true] : []);
}

function current_user(bool $readOnly = false): ?string
{
    start_session($readOnly);
    $user = $_SESSION['user'] ?? null;
    if ($user === null) {
        return null;
    }

    $idle = time() - (int) ($_SESSION['last_seen'] ?? 0);
    if ($idle > (int) config('session_idle_timeout') || !users()->exists($user)) {
        if (!$readOnly) {
            logout();
        }
        return null;
    }

    if (!$readOnly) {
        $_SESSION['last_seen'] = time();
    }
    return $user;
}

/** Store messages and form input to show on the next page load (post/redirect/get). */
function flash(array $data): void
{
    start_session();
    $_SESSION['flash'] = $data;
}

function take_flash(): array
{
    start_session();
    $data = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $data;
}

function require_login(): string
{
    $user = current_user();
    if ($user === null) {
        header('Location: login.php');
        exit;
    }
    return $user;
}

function login(string $username): void
{
    start_session();
    session_regenerate_id(true);
    $_SESSION = ['user' => $username, 'last_seen' => time()];
}

function logout(): void
{
    start_session();
    $_SESSION = [];
    session_regenerate_id(true);
}

function csrf_token(): string
{
    start_session();
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
}

function csrf_valid(): bool
{
    if (!isset($_SESSION)) {
        start_session(); // Otherwise use the already-loaded (possibly read-only) session.
    }
    $sent = $_POST['csrf'] ?? '';
    return is_string($sent) && isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $sent);
}

function send_security_headers(): void
{
    header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
}
