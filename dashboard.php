<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();
$lastLogin = $user['last_login_at'] === null
    ? 'Not available'
    : date('F j, Y, g:i a', strtotime((string) $user['last_login_at']));
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="dashboard-title">
        <?php render_nav(); ?>
        <div class="auth-heading">
            <p class="eyebrow">Account</p>
            <h1 id="dashboard-title">Welcome, <?= e((string) $user['name']) ?></h1>
            <p class="muted">Your account is ready.</p>
        </div>
        <dl class="account-details">
            <div><dt>Name</dt><dd><?= e((string) $user['name']) ?></dd></div>
            <div><dt>Email</dt><dd><?= e((string) $user['email']) ?></dd></div>
            <div><dt>Role</dt><dd><?= e((string) $user['role']) ?></dd></div>
            <div><dt>Member since</dt><dd><?= e((string) $user['created_at']) ?></dd></div>
            <div><dt>Last login</dt><dd><?= e($lastLogin) ?></dd></div>
        </dl>
    </section>
</main>
</body>
</html>
