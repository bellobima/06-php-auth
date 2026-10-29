<?php
declare(strict_types=1);

function current_user(): ?array
{
    static $loaded = false;
    static $user = null;

    if ($loaded) {
        return $user;
    }

    $loaded = true;
    $userId = $_SESSION['user_id'] ?? null;

    if (!is_int($userId) || $userId < 1) {
        return null;
    }

    $statement = db()->prepare(
        'SELECT id, name, email, role, created_at, last_login_at FROM users WHERE id = :id LIMIT 1'
    );
    $statement->execute(['id' => $userId]);
    $record = $statement->fetch();

    if ($record === false) {
        unset($_SESSION['user_id'], $_SESSION['user_role'], $_SESSION['user_name']);
        return null;
    }

    $_SESSION['user_role'] = (string) $record['role'];
    $_SESSION['user_name'] = (string) $record['name'];
    $user = $record;

    return $user;
}

function require_login(): void
{
    if (current_user() !== null) {
        return;
    }

    $requestUri = $_SERVER['REQUEST_URI'] ?? null;
    $intendedUrl = valid_intended_url($requestUri);
    unset($_SESSION['_intended_url']);

    if ($intendedUrl !== null && !str_ends_with(parse_url($intendedUrl, PHP_URL_PATH) ?: '', '/login.php')) {
        $_SESSION['_intended_url'] = $intendedUrl;
    }

    redirect('login.php');
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('dashboard.php');
    }
}

function require_role(string $role = 'admin'): void
{
    require_login();

    if (($_SESSION['user_role'] ?? null) !== $role) {
        http_response_code(403);
        $scriptDirectory = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
        $appBase = preg_replace('~/admin$~', '', $scriptDirectory);
        $dashboardUrl = rtrim(is_string($appBase) ? $appBase : '', '/') . '/dashboard.php';
        ?>
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Access denied</title>
            <link rel="stylesheet" href="../assets/auth.css">
        </head>
        <body>
        <main class="auth-page">
            <section class="auth-card" aria-labelledby="forbidden-title">
                <div class="auth-heading">
                    <p class="eyebrow">403 · Access denied</p>
                    <h1 id="forbidden-title">This area is for admins</h1>
                    <p class="muted">Your account does not have permission to view this page.</p>
                </div>
                <a class="button-link" href="<?= e($dashboardUrl) ?>">Return to your dashboard</a>
            </section>
        </main>
        </body>
        </html>
        <?php
        exit;
    }
}

function login_throttle_minutes(string $email, string $ipAddress): ?int
{
    $query = db()->prepare(
        'SELECT COUNT(*) AS failure_count, '
        . 'CEIL((900 - TIMESTAMPDIFF(SECOND, MIN(attempted_at), CURRENT_TIMESTAMP)) / 60) AS wait_minutes '
        . 'FROM login_attempts '
        . 'WHERE email = :email AND was_successful = 0 '
        . 'AND attempted_at >= CURRENT_TIMESTAMP - INTERVAL 15 MINUTE'
    );
    $query->execute(['email' => $email]);
    $emailAttempts = $query->fetch();

    $query = db()->prepare(
        'SELECT COUNT(*) AS failure_count, '
        . 'CEIL((900 - TIMESTAMPDIFF(SECOND, MIN(attempted_at), CURRENT_TIMESTAMP)) / 60) AS wait_minutes '
        . 'FROM login_attempts '
        . 'WHERE ip_address = :ip_address AND was_successful = 0 '
        . 'AND attempted_at >= CURRENT_TIMESTAMP - INTERVAL 15 MINUTE'
    );
    $query->execute(['ip_address' => $ipAddress]);
    $ipAttempts = $query->fetch();

    $waitTimes = [];
    foreach ([$emailAttempts, $ipAttempts] as $attempts) {
        if ($attempts !== false && (int) $attempts['failure_count'] >= 5) {
            $waitTimes[] = max(1, (int) $attempts['wait_minutes']);
        }
    }

    return $waitTimes === [] ? null : max($waitTimes);
}

function record_failed_login(string $email, string $ipAddress): void
{
    $statement = db()->prepare(
        'INSERT INTO login_attempts (email, ip_address, was_successful) VALUES (:email, :ip_address, 0)'
    );
    $statement->execute([
        'email' => mb_substr($email, 0, 254),
        'ip_address' => $ipAddress,
    ]);
}

function clear_login_attempts(string $email, string $ipAddress): void
{
    $statement = db()->prepare(
        'DELETE FROM login_attempts WHERE email = :email OR ip_address = :ip_address'
    );
    $statement->execute([
        'email' => $email,
        'ip_address' => $ipAddress,
    ]);
}

function valid_intended_url(mixed $url): ?string
{
    if (!is_string($url)
        || $url === ''
        || preg_match('/[\x00-\x1F\x7F\\\\]/', $url) === 1
        || preg_match('/%(?:0[0-9a-f]|1[0-9a-f]|7f|5c)/i', $url) === 1) {
        return null;
    }

    $parts = parse_url($url);
    if ($parts === false
        || isset($parts['scheme'])
        || isset($parts['host'])
        || isset($parts['user'])
        || isset($parts['pass'])
        || !isset($parts['path'])
        || !str_starts_with($parts['path'], '/')
        || str_starts_with($parts['path'], '//')) {
        return null;
    }

    return $url;
}

function end_session(?string $message = null): void
{
    $_SESSION = [];

    $cookie = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires' => time() - 42000,
        'path' => $cookie['path'],
        'domain' => $cookie['domain'],
        'secure' => $cookie['secure'],
        'httponly' => $cookie['httponly'],
        'samesite' => $cookie['samesite'] ?? 'Lax',
    ]);

    session_destroy();
    session_start();
    session_regenerate_id(true);

    if ($message !== null) {
        flash('status', $message);
    }
}
