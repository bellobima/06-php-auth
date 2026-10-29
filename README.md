# SWD PHP Authentication

PHP 8 authentication example for XAMPP and MySQL. The application database is
`swd_auth`.

## Setup

1. Copy the project into `C:\xampp\htdocs\swd\06-php-auth`.
2. Import `schema.sql` in phpMyAdmin or run it with the MySQL command-line client.
   The schema creates the `users` and `login_attempts` tables.
3. Configure the database constants in `config/config.php` for your local XAMPP
   MySQL account. The defaults are for a standard local XAMPP installation.
4. Open `http://localhost/swd/06-php-auth/register.php` to create an account.
5. Promote the account that should administer the site from a terminal:

   ```powershell
   & 'C:\xampp\php\php.exe' 'C:\xampp\htdocs\swd\06-php-auth\promote-admin.php' 'me@example.com'
   ```

To update a database created from the Stage 3 schema, run `migrate_stage4.sql`
once. For a fresh install, use `schema.sql` instead of migration scripts.

## Security features

- Passwords are stored with PHP's `password_hash()` and checked with
  `password_verify()`. Password changes require the current password and
  increment a per-user session version, invalidating other active sessions.
- Sessions use a dedicated name, strict mode, HTTP-only and SameSite=Lax
  cookies, HTTPS-only cookies on HTTPS requests, ID regeneration after
  authentication and password changes, and a 30-minute idle timeout.
- CSRF tokens protect state-changing forms. User-provided values are escaped
  for HTML output, and database operations use PDO prepared statements.
- Intended post-login destinations are restricted to relative same-site paths.
- Login failures are recorded by email and IP. Five failures in a rolling
  15-minute window trigger a temporary lockout.
- Admin routes check the user's role on each request. Role changes are
  CSRF-protected, and admins cannot demote their own account.
- Responses set `X-Frame-Options`, `X-Content-Type-Options`, and
  `Referrer-Policy`. HSTS is sent only over HTTPS.
- Production configuration disables displayed PHP errors and requires HTTPS.
  Loopback hosts (`localhost`, `127.0.0.1`, and `[::1]`) are exempt for local
  XAMPP development. Set `APP_ENV=development` to display errors locally; set
  `APP_REQUIRE_HTTPS=0` only when intentionally working over HTTP.

## Production deployment

Use HTTPS with a valid certificate and configure Apache (or the trusted
reverse proxy) so PHP receives the actual HTTPS state in `$_SERVER['HTTPS']`.
Do not expose this project over plain HTTP. Use a dedicated MySQL account with
only the required privileges; do not use XAMPP's empty-password `root` account
for an internet-facing deployment. Keep database credentials out of public
source control and configure them in a protected deployment-specific
configuration.

The starter configuration is intended for local XAMPP. Before public
deployment, change `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASS` in
`config/config.php` to the production database settings and review the web
server's TLS, PHP error logging, backups, and access controls.
