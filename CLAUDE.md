# php-ssl-scanner

PHP utility for scanning SSL certificates and reporting on upcoming expirations.

## Development

- Plain PHP 8.1+, no Composer dependencies. Web root is `public/`; classes live in `src/` under the `SslScanner` namespace.
- Run `php tests/run.php` before committing.

## Git workflow

- Commit and push directly to the `main` branch.
- Do not create feature branches or pull requests unless explicitly asked.
