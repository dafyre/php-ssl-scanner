<?php

declare(strict_types=1);

namespace SslScanner;

use InvalidArgumentException;
use RuntimeException;

/**
 * Stores user accounts in a JSON file, with bcrypt/argon password hashes.
 */
final class UserStore
{
    public function __construct(private string $file)
    {
    }

    public function exists(string $username): bool
    {
        return isset($this->load()[$username]);
    }

    /** @return list<string> */
    public function list(): array
    {
        $names = array_keys($this->load());
        sort($names);
        return $names;
    }

    public function verify(string $username, string $password): bool
    {
        $users = $this->load();
        $hash = $users[$username]['hash'] ?? null;

        if ($hash === null) {
            // Spend the same time as a real check so usernames can't be probed by timing.
            password_verify($password, '$2y$10$NqH/6sIm1EFoBg/e3LOKHexYTeO9DBVjnU1W7/ljtglpdzordsOuC');
            return false;
        }

        if (!password_verify($password, $hash)) {
            return false;
        }

        if (password_needs_rehash($hash, PASSWORD_DEFAULT)) {
            $this->mutate(function (array $users) use ($username, $password) {
                $users[$username]['hash'] = password_hash($password, PASSWORD_DEFAULT);
                return $users;
            });
        }
        return true;
    }

    public function setPassword(string $username, string $password, bool $create): void
    {
        self::assertValidUsername($username);
        if (strlen($password) < 8) {
            throw new InvalidArgumentException('Passwords must be at least 8 characters.');
        }

        $this->mutate(function (array $users) use ($username, $password, $create) {
            if ($create && isset($users[$username])) {
                throw new InvalidArgumentException("User \"{$username}\" already exists.");
            }
            if (!$create && !isset($users[$username])) {
                throw new InvalidArgumentException("User \"{$username}\" does not exist.");
            }
            $users[$username] = [
                'hash' => password_hash($password, PASSWORD_DEFAULT),
                'created' => $users[$username]['created'] ?? date('c'),
                'updated' => date('c'),
            ];
            return $users;
        });
    }

    public function delete(string $username): void
    {
        $this->mutate(function (array $users) use ($username) {
            if (!isset($users[$username])) {
                throw new InvalidArgumentException("User \"{$username}\" does not exist.");
            }
            unset($users[$username]);
            return $users;
        });
    }

    public static function assertValidUsername(string $username): void
    {
        if (!preg_match('/^[A-Za-z0-9._@-]{1,64}$/', $username)) {
            throw new InvalidArgumentException('Usernames may contain letters, digits, and . _ @ - (max 64 characters).');
        }
    }

    private function load(): array
    {
        if (!is_file($this->file)) {
            return [];
        }
        if (!is_readable($this->file)) {
            error_log("[ssl-scanner] Cannot read {$this->file}; check its owner and permissions.");
            return [];
        }
        $data = json_decode((string) file_get_contents($this->file), true);
        return is_array($data) ? $data : [];
    }

    private function mutate(callable $change): void
    {
        $dir = dirname($this->file);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException("Could not create data directory {$dir}.");
        }

        $fh = fopen($this->file, 'c+');
        if ($fh === false) {
            throw new RuntimeException("Could not open {$this->file}.");
        }
        try {
            flock($fh, LOCK_EX);
            $data = json_decode((string) stream_get_contents($fh), true);
            $users = $change(is_array($data) ? $data : []);
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, json_encode($users, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
            fflush($fh);
            @chmod($this->file, 0600);
            FileOwner::matchParent($this->file);
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }
}
