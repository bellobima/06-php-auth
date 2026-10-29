<?php
declare(strict_types=1);

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/src/db.php';
require_once __DIR__ . '/src/helpers.php';
require_once __DIR__ . '/src/csrf.php';
require_once __DIR__ . '/src/auth.php';
require_once __DIR__ . '/src/nav.php';

error_reporting(E_ALL);
ini_set('display_errors', APP_ENV === 'development' ? '1' : '0');

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

$requestHost = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
$hostWithoutPort = preg_replace('/:\d+$/', '', $requestHost);
$isLocalHost = in_array($hostWithoutPort, ['localhost', '127.0.0.1', '[::1]'], true);
$isHttps = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && $_SERVER['HTTPS'] !== 'off';

if (APP_REQUIRE_HTTPS && !$isHttps && !$isLocalHost && PHP_SAPI !== 'cli') {
    $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
    if (!is_string($requestUri) || preg_match('/[\x00-\x20\x7F\\\\]/', $requestUri) === 1) {
        http_response_code(400);
        exit('Invalid request URI.');
    }

    $safeHost = preg_match('/^(?:[a-z0-9.-]+|\[[0-9a-f:]+\])(?::\d{1,5})?$/', $requestHost) === 1;
    if (!$safeHost) {
        http_response_code(400);
        exit('Invalid request host.');
    }

    header('Location: https://' . $requestHost . $requestUri, true, 308);
    exit;
}

if ($isHttps) {
    header('Strict-Transport-Security: max-age=31536000');
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    session_name('SWDSESSID');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}

if (isset($_SESSION['user_id'])) {
    $now = time();
    $lastActivity = $_SESSION['_last_activity'] ?? $now;

    if (!is_int($lastActivity) || $now - $lastActivity >= 1800) {
        end_session('You were signed out after 30 minutes of inactivity.');
    } else {
        $_SESSION['_last_activity'] = $now;
    }
}
