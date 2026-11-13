<?php

declare(strict_types=1);

namespace SslScanner;

use InvalidArgumentException;

/** Scan input that can't be scanned, along with any warnings about ignored entries. */
final class ScanInputError extends InvalidArgumentException
{
    /** @param list<string> $warnings */
    public function __construct(string $message, public readonly array $warnings = [])
    {
        parent::__construct($message);
    }
}
