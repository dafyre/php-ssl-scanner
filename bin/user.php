<?php

declare(strict_types=1);

// Manage scanner user accounts from the command line.
//
//   php bin/user.php add <username>       Create a user (prompts for password)
//   php bin/user.php passwd <username>    Change a user's password
//   php bin/user.php delete <username>    Remove a user
//   php bin/user.php list                 List users
//
// Set SSL_SCANNER_PASSWORD to supply the password non-interactively.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

function prompt_password(string $label): string
{
    $env = getenv('SSL_SCANNER_PASSWORD');
    if ($env !== false && $env !== '') {
        return $env;
    }

    $interactive = function_exists('posix_isatty') ? posix_isatty(STDIN) : stream_isatty(STDIN);
    fwrite(STDOUT, $label);
    if ($interactive) {
        shell_exec('stty -echo');
    }
    $password = rtrim((string) fgets(STDIN), "\r\n");
    if ($interactive) {
        shell_exec('stty echo');
        fwrite(STDOUT, PHP_EOL);
    }
    return $password;
}

function read_new_password(): string
{
    $first = prompt_password('Password: ');
    if (getenv('SSL_SCANNER_PASSWORD') === false || getenv('SSL_SCANNER_PASSWORD') === '') {
        $second = prompt_password('Confirm password: ');
        if (!hash_equals($first, $second)) {
            throw new InvalidArgumentException('Passwords do not match.');
        }
    }
    return $first;
}

$command = $argv[1] ?? '';
$username = $argv[2] ?? '';

try {
    switch ($command) {
        case 'add':
        case 'passwd':
            if ($username === '') {
                throw new InvalidArgumentException("Usage: php bin/user.php {$command} <username>");
            }
            users()->setPassword($username, read_new_password(), $command === 'add');
            echo $command === 'add' ? "Created user {$username}.\n" : "Updated password for {$username}.\n";
            break;

        case 'delete':
            if ($username === '') {
                throw new InvalidArgumentException('Usage: php bin/user.php delete <username>');
            }
            users()->delete($username);
            echo "Deleted user {$username}.\n";
            break;

        case 'list':
            $names = users()->list();
            echo $names === [] ? "No users yet. Create one with: php bin/user.php add <username>\n" : implode(PHP_EOL, $names) . PHP_EOL;
            break;

        default:
            fwrite(STDERR, "Usage: php bin/user.php add|passwd|delete <username>\n       php bin/user.php list\n");
            exit(2);
    }
} catch (InvalidArgumentException|RuntimeException $e) {
    fwrite(STDERR, 'Error: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}
