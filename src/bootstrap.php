<?php

declare(strict_types=1);

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

/** Escape for HTML output. */
function h(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function start_session(): void
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
    session_start();
}

function current_user(): ?string
{
    start_session();
    $user = $_SESSION['user'] ?? null;
    if ($user === null) {
        return null;
    }

    $idle = time() - (int) ($_SESSION['last_seen'] ?? 0);
    if ($idle > (int) config('session_idle_timeout') || !users()->exists($user)) {
        logout();
        return null;
    }

    $_SESSION['last_seen'] = time();
    return $user;
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
    start_session();
    $sent = $_POST['csrf'] ?? '';
    return is_string($sent) && isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $sent);
}

function send_security_headers(): void
{
    header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
}
