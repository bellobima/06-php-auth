<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/src/db.php';

$email = $argv[1] ?? '';
if (!is_string($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Usage: php promote-admin.php user@example.com\n");
    exit(2);
}

$statement = db()->prepare('UPDATE users SET role = :role WHERE email = :email');
$statement->execute(['role' => 'admin', 'email' => $email]);

if ($statement->rowCount() === 0) {
    $check = db()->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $check->execute(['email' => $email]);

    if ($check->fetch() === false) {
        fwrite(STDERR, "No user found with that email address.\n");
        exit(1);
    }
}

fwrite(STDOUT, "Admin role granted to {$email}.\n");
