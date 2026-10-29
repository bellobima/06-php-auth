<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (!isset($_SESSION['user_id']) || !is_int($_SESSION['user_id'])) {
    redirect('register.php');
}
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
        <div class="auth-heading">
            <p class="eyebrow">Account</p>
            <h1 id="dashboard-title">Welcome, <?= e($_SESSION['user_name'] ?? 'there') ?></h1>
            <p class="muted">Your account is ready.</p>
        </div>
    </section>
</main>
</body>
</html>
