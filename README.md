# PHP SSL Scanner

A small, dependency-free PHP web app for finding TLS/SSL certificates on your network and spotting the ones that are about to expire.

Enter hostnames, IP addresses, or whole subnets in CIDR notation, plus a list of ports. The scanner checks every address and port combination in parallel. For each certificate it finds, it shows:

- Common name (CN)
- Subject alternative names (SANs)
- Issuer (and whether the certificate is self-signed)
- Issue date and expiration date
- Days until expiry, highlighted red if expired and amber if expiring soon

While a scan runs, a progress bar shows how many address/port checks are done, certificates found so far, elapsed time, and an estimate of the time left. A **Cancel** button stops the scan and keeps the partial results.

Results can be filtered, sorted by any column, and downloaded as CSV. Runs can be saved by name and loaded later, downloaded and imported as JSON, or re-run on a schedule from cron with an emailed report. Your most recent scan stays on the page when you come back. The app requires a username and password.

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

2. **Create the data folder and your first user, as the web server's user.** The app stores accounts, saved runs, and scan results in `data/`, and the web server must be able to read and write it. The web server user is usually `www-data` on Debian/Ubuntu and `apache` on RHEL/CentOS/Fedora.

   ```sh
   sudo -u www-data php bin/user.php add admin
   ```

   You'll be prompted for a password (minimum 8 characters). If you've already created users as root or as yourself, fix the ownership with:

   ```sh
   sudo chown -R www-data:www-data data
   ```

3. **Point your web server's document root at `public/`.** Only that folder should be web-accessible; `src/`, `config/`, `data/`, and `bin/` must not be.

   For a quick local try-out:

   ```sh
   PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:8080 -t public
   ```

   The progress bar polls the server while a scan runs, so the server must handle more than one request at a time. PHP's built-in server only does that when `PHP_CLI_SERVER_WORKERS` is set. Apache, and nginx with PHP-FPM, handle this by default.

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

Run these as the web server user (for example `sudo -u www-data php bin/user.php ...`). If you run them as root, the script keeps the files owned by whoever owns `data/`, and warns you if that's root.

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

- Connections run in parallel (64 at a time by default), each with a 4-second connect timeout and a separate 4-second handshake timeout. A /24 on a few ports with live hosts usually finishes in seconds. Addresses that don't answer at all take the full timeout, so a mostly empty /24 across several ports can take a minute or two.
- Certificate validation is **intentionally disabled**. The goal is to report what each server presents, including expired, self-signed, and mismatched certificates, not to decide whether to trust it. Legacy protocols and ciphers are allowed so older appliances still report their certificates.
- When a target is a hostname, its name is sent as SNI so you get the certificate for that site. Bare IPs and CIDR ranges are scanned without SNI, which returns each server's default certificate.

## Filtering results

The filter bar above the results narrows the table instantly:

- **Search** matches host, IP, common name, any SAN, issuer, or error message. Several words must all match.
- **Status** chips: Expired, Expiring (within the `warn_days` setting, 30 by default), Valid, and No certificate. Addresses with no certificate are hidden by default.
- **Port**, **Issuer**, and **Self-signed** dropdowns.
- **Expires within N days** shows only certificates expiring in that window, including ones that have already expired.

**Download CSV** exports exactly the rows that match the current filters; the button shows how many.

## Saving and loading runs

- **Save run** (next to the results) stores the current scan under a name. Leave the name blank to use the targets and date.
- **Saved runs** (top menu) lists your runs with how many certificates are expired or expiring *as of today*. From there you can load, rename, download, or delete a run.
- **Loading** a run puts it on the scan page, so you can filter and export it. The form is pre-filled with that run's targets and ports, so pressing **Scan** re-runs it.
- **Download JSON** saves a run to a file. **Import a run** on the Saved runs page loads such a file back, for example on another server or from a backup. Imported files are validated before they're accepted.

Saved runs are private to each user and stored in `data/scans/`.

## Scheduled scans (cron)

`bin/run-saved.php` re-runs a saved run by name from the command line. Each run:

1. Re-scans that run's targets and ports. Hostnames are looked up again, so DNS changes are picked up.
2. Saves the new results back into the saved run, so the web page shows them. The Saved runs list marks it **by schedule**.
3. Prints a plain-text report: expired and expiring certificates, plus what changed since the previous run (certificates renewed or replaced, new ones, and ones that stopped answering).

Cron emails anything a job prints to the crontab's `MAILTO` address, so the report becomes your email. With `--quiet`, the script prints nothing unless a certificate has expired or expires within `warn_days`, so you only get email when something needs attention.

**Set it up** in the web server user's crontab, so the files it writes stay readable by the web app:

```sh
sudo crontab -u www-data -e
```

```cron
MAILTO=ops@example.com
# Every day at 07:00
0 7 * * *  php /var/www/php-ssl-scanner/bin/run-saved.php --quiet "Production"
```

The **Schedule** button on the Saved runs page shows this line for each run, with the correct path, ready to copy. If you do run it from root's crontab instead, new files are given to the owner of `data/` so the web app can still read them.

**Options**

| Option | What it does |
| --- | --- |
| `--quiet` | Print nothing unless something has expired or is expiring |
| `--all` | Also list valid certificates in the report |
| `--warn-days=N` | Use N days as the "expiring" window instead of `warn_days` |
| `--csv=FILE` | Also write the results as CSV; `{date}` in the name becomes the scan date, e.g. `--csv=/var/reports/ssl-{date}.csv` |
| `--no-save` | Scan and report without updating the saved run |
| `--user=NAME` | Owner of the run, if several users have a run with the same name |
| `--id=ID` | Pick the run by id instead of name. Ids don't change when a run is renamed |
| `--list` | List saved runs with their ids and owners |

Names are matched ignoring case and extra spaces. If a run is renamed in the web app, update the crontab, or use `--id` so it doesn't matter.

**Exit status** follows the Nagios convention, so the script can also feed a monitoring system: `0` nothing expiring, `1` something expires within the warning window, `2` something has expired, `3` error (run not found, already running, invalid targets, and so on). If a scan of the same run is still going when the next one starts, the second exits with status 3 instead of overlapping.

## How progress works

The scan page sends the scan request in the background and polls `progress.php` about once a second. The running scan writes its progress to a small file in `data/scans/`. Each user's latest results are saved there too, so they're still available after a page reload, and the CSV export uses them.

If the browser is closed or the connection drops mid-scan, the scan keeps running on the server and its results appear the next time you open the page. Use **Cancel** to stop a scan. Very large scans can outlast proxy timeouts, so set your web server's FastCGI or proxy read timeout high enough (the nginx example uses 600 seconds).

Without JavaScript, the form still works as a normal submit; it just doesn't show progress.

## Security notes

- Passwords are hashed with PHP's `password_hash()` (bcrypt by default).
- After 5 failed logins within 15 minutes, an IP address is locked out for the rest of that window.
- All forms are protected with CSRF tokens. Sessions are HTTP-only and `SameSite=Strict`, and they time out after 30 minutes of inactivity.
- Anyone with an account can make the server connect to arbitrary addresses and ports. Only give accounts to people you trust with that, and consider network-level restrictions on where the server may connect.

## Troubleshooting

**"No users exist yet" even though you created one, or every login fails.** The web server can't read `data/`. This usually happens when `bin/user.php` was run as root or under your own account. The login page shows a **Setup problem** message with the exact command to fix it, typically:

```sh
sudo chown -R www-data:www-data /path/to/php-ssl-scanner/data
```

The same message is written to PHP's error log.

**A scheduled run fails with "can't read and write the data folder".** The crontab belongs to a different user than the one that owns `data/`. The error says which user owns it. Move the line to that user's crontab (`sudo crontab -u www-data -e`).

**The progress bar doesn't move during a scan.** The web server is handling one request at a time. See the note about `PHP_CLI_SERVER_WORKERS` under Setup.

## Development

Run the tests:

```sh
php tests/run.php
```

Project layout:

```
public/      web root: scan page, saved runs, CSV export, progress endpoint, CSS, JS
src/         TargetParser (input parsing, CIDR expansion), Scanner (parallel TLS),
             ScanJob (validate + run a scan), ScanStore (progress, latest results,
             saved runs, import validation), Report (cron report), CsvExport,
             UserStore, LoginThrottle, FileOwner, bootstrap helpers
templates/   shared page header and footer
bin/         user.php (manage users), run-saved.php (re-run a saved run, e.g. from cron)
config/      config.example.php (copy to config.php)
data/        runtime data: users, login throttle, scan progress, results, saved runs (git-ignored)
tests/       dependency-free tests
```
