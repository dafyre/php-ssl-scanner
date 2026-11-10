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

/**
 * Running this script as root creates data/ owned by root, which the web server can't
 * read, so every login fails. Spot that and print the fix.
 */
function warn_if_root_owned(): void
{
    if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
        return;
    }
    $dir = (string) config('data_dir');
    if (fileowner($dir) === 0) {
        fwrite(STDERR, <<<TXT

        Warning: {$dir} is owned by root, so the web server can't read it and logins will fail.
        Give it to the web server user, e.g.:

            sudo chown -R www-data:www-data {$dir}     (Debian/Ubuntu)
            sudo chown -R apache:apache {$dir}         (RHEL/CentOS/Fedora)

        Next time, run this script as that user: sudo -u www-data php bin/user.php ...

        TXT);
    }
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
            warn_if_root_owned();
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
