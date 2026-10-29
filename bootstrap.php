<?php
declare(strict_types=1);

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/src/db.php';
require_once __DIR__ . '/src/helpers.php';
require_once __DIR__ . '/src/csrf.php';
require_once __DIR__ . '/src/auth.php';

error_reporting(E_ALL);
ini_set('display_errors', APP_ENV === 'development' ? '1' : '0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    session_name('SWDSESSID');

    $isHttps = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && $_SERVER['HTTPS'] !== 'off';
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
