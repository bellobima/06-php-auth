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
        echo 'Forbidden';
        exit;
    }
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
