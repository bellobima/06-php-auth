<?php
declare(strict_types=1);

function render_nav(): void
{
    $user = current_user();
    if ($user === null) {
        return;
    }

    $scriptDirectory = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
    $appBase = preg_replace('~/admin$~', '', $scriptDirectory);
    $base = rtrim(is_string($appBase) ? $appBase : '', '/');
    ?>
    <nav class="site-nav" aria-label="Main navigation">
        <a href="<?= e($base . '/dashboard.php') ?>">Dashboard</a>
        <a href="<?= e($base . '/profile.php') ?>">Profile</a>
        <?php if ($user['role'] === 'admin'): ?>
            <a href="<?= e($base . '/admin/users.php') ?>">Admin</a>
        <?php endif; ?>
        <form method="post" action="<?= e($base . '/logout.php') ?>">
            <?= csrf_field() ?>
            <button type="submit">Sign out</button>
        </form>
    </nav>
    <?php
}
