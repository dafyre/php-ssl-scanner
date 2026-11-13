<?php

declare(strict_types=1);

namespace SslScanner;

/**
 * Keeps data files owned by the web server user when a script runs as root (for example
 * `sudo php bin/user.php` or a root crontab). Otherwise root would end up owning files
 * that Apache/PHP-FPM then can't read or write.
 */
final class FileOwner
{
    /** If running as root, give $path to whoever owns its parent directory. */
    public static function matchParent(string $path): void
    {
        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0 || !file_exists($path)) {
            return;
        }
        $parent = dirname($path);
        $uid = @fileowner($parent);
        $gid = @filegroup($parent);
        if ($uid !== false && $uid !== 0) {
            @chown($path, $uid);
            if ($gid !== false) {
                @chgrp($path, $gid);
            }
        }
    }
}
