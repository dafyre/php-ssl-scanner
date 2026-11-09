<?php

// Copy this file to config/config.php and adjust as needed.
// Any setting left out falls back to the default in src/bootstrap.php.

return [
    // Name shown in the page header and browser tab.
    'app_name' => 'SSL Certificate Scanner',

    // Where user accounts and login-throttle data are stored. Keep this outside the web root.
    'data_dir' => __DIR__ . '/../data',

    // Seconds to wait for each TCP connect and, separately, each TLS handshake.
    'timeout' => 4.0,

    // How many connections to keep open at once.
    'concurrency' => 64,

    // Upper bounds for a single scan.
    'max_hosts' => 1024,
    'max_ports' => 64,
    'max_checks' => 8192, // hosts x ports

    // Certificates expiring within this many days are highlighted as "expiring soon".
    'warn_days' => 30,

    // Log users out after this many seconds of inactivity.
    'session_idle_timeout' => 1800,

    // Lock out an IP address after this many failed logins within the window (seconds).
    'login_max_attempts' => 5,
    'login_lockout_window' => 900,

    // Default values pre-filled in the scan form.
    'default_ports' => '443',
];
