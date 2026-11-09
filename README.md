# PHP SSL Scanner

A small, dependency-free PHP web app for finding TLS/SSL certificates on your network and spotting the ones that are about to expire.

Enter hostnames, IP addresses, or whole subnets in CIDR notation, plus a list of ports. The scanner checks every address and port combination in parallel. For each certificate it finds, it shows:

- Common name (CN)
- Subject alternative names (SANs)
- Issuer (and whether the certificate is self-signed)
- Issue date and expiration date
- Days until expiry, highlighted red if expired and amber if expiring soon

Results can be sorted by any column and downloaded as CSV. The app requires a username and password.

## Requirements

- PHP 8.1 or newer with the `openssl` extension (enabled by default in most builds)
- A web server that runs PHP (Apache, nginx + PHP-FPM, Caddy, or PHP's built-in server for testing)
- No Composer packages and no database

## Setup

1. **Clone the repo** somewhere on the server:

   ```sh
   git clone https://github.com/dafyre/php-ssl-scanner.git
   cd php-ssl-scanner
   ```

2. **Create a user** (you'll be prompted for a password, minimum 8 characters):

   ```sh
   php bin/user.php add admin
   ```

   Accounts are stored with hashed passwords in `data/users.json`. The web server user needs read/write access to `data/`.

3. **Point your web server's document root at `public/`.** Only that folder should be web-accessible; `src/`, `config/`, `data/`, and `bin/` must not be.

   For a quick local try-out:

   ```sh
   php -S 127.0.0.1:8080 -t public
   ```

   Then open <http://127.0.0.1:8080>.

4. **Optional:** copy `config/config.example.php` to `config/config.php` and adjust timeouts, limits, the "expiring soon" threshold, and so on.

Serve the app over HTTPS in production. Session cookies are automatically marked `Secure` when the request arrives over HTTPS.

### Example nginx server block

```nginx
server {
    listen 443 ssl;
    server_name sslscan.example.com;
    root /var/www/php-ssl-scanner/public;
    index index.php;

    location / { try_files $uri $uri/ =404; }
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_read_timeout 600;   # large scans can take a few minutes
    }
}
```

## Managing users

```sh
php bin/user.php add <username>      # create a user
php bin/user.php passwd <username>   # change a password
php bin/user.php delete <username>   # remove a user
php bin/user.php list                # list users
```

For scripted setups, set `SSL_SCANNER_PASSWORD` to supply the password without a prompt.

## Input format

**Targets** can be separated by commas, spaces, or new lines:

| Input | Scanned as |
| --- | --- |
| `example.com` | Every IPv4 address the name resolves to (falls back to IPv6), using the name for SNI |
| `10.0.0.15`, `2001:db8::5` | That single address |
| `192.168.1.0/24` | Every usable address in the range (network and broadcast addresses are skipped for IPv4 /30 and larger) |

**Ports** can be single ports or ranges: `443, 8443, 9000-9010`.

Default limits per scan are 1024 addresses, 64 ports, and 8192 total address/port checks. All of these can be changed in `config/config.php`.

## How scanning works

- Connections run in parallel (64 at a time by default), each with a 4-second connect timeout and a separate 4-second handshake timeout. A /24 on a few ports usually finishes in seconds.
- Certificate validation is **intentionally disabled**. The goal is to report what each server presents, including expired, self-signed, and mismatched certificates, not to decide whether to trust it. Legacy protocols and ciphers are allowed so older appliances still report their certificates.
- When a target is a hostname, its name is sent as SNI so you get the certificate for that site. Bare IPs and CIDR ranges are scanned without SNI, which returns each server's default certificate.

## Security notes

- Passwords are hashed with PHP's `password_hash()` (bcrypt by default).
- After 5 failed logins within 15 minutes, an IP address is locked out for the rest of that window.
- All forms are protected with CSRF tokens. Sessions are HTTP-only and `SameSite=Strict`, and they time out after 30 minutes of inactivity.
- Anyone with an account can make the server connect to arbitrary addresses and ports. Only give accounts to people you trust with that, and consider network-level restrictions on where the server may connect.

## Development

Run the tests:

```sh
php tests/run.php
```

Project layout:

```
public/      web root: pages, CSS, JS
src/         TargetParser (input parsing, CIDR expansion), Scanner (parallel TLS),
             UserStore, LoginThrottle, bootstrap helpers
templates/   shared page header and footer
bin/         command-line user management
config/      config.example.php (copy to config.php)
data/        runtime data: users and login throttle (git-ignored)
tests/       dependency-free tests
```
