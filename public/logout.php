<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

// Only log out on POST with a valid token, so a stray link can't sign someone out.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && csrf_valid()) {
    logout();
}

header('Location: login.php');
