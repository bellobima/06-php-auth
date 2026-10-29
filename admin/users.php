<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap.php';

require_role('admin');
$admin = current_user();
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedToken = $_POST['_csrf_token'] ?? null;
    if (!csrf_verify(is_string($postedToken) ? $postedToken : null)) {
        http_response_code(419);
        $errors[] = 'Your form session expired. Reload the page and try again.';
    } else {
        $userId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
        $roleInput = $_POST['role'] ?? null;
        $role = is_string($roleInput) ? $roleInput : '';

        if ($userId === false || $userId === null || $userId < 1 || !in_array($role, ['user', 'admin'], true)) {
            http_response_code(400);
            $errors[] = 'Choose a valid user and role.';
        } elseif ((int) $userId === (int) $admin['id'] && $role !== 'admin') {
            http_response_code(400);
            $errors[] = 'You cannot remove your own admin role.';
        } else {
            $update = db()->prepare('UPDATE users SET role = :role WHERE id = :id');
            $update->execute(['role' => $role, 'id' => (int) $userId]);

            if ($update->rowCount() === 0) {
                $exists = db()->prepare('SELECT id FROM users WHERE id = :id LIMIT 1');
                $exists->execute(['id' => (int) $userId]);
                if ($exists->fetch() === false) {
                    http_response_code(404);
                    $errors[] = 'That user no longer exists.';
                } else {
                    flash('status', 'That user already has the selected role.');
                    redirect('users.php');
                }
            } else {
                flash('status', 'User role updated.');
                redirect('users.php');
            }
        }
    }
}

$statusMessage = flash('status');
$users = db()->query(
    'SELECT id, name, email, role, created_at, last_login_at FROM users ORDER BY name, id'
)->fetchAll();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage users</title>
    <link rel="stylesheet" href="../assets/auth.css">
</head>
<body>
<main class="auth-page auth-page-wide">
    <section class="auth-card auth-card-wide" aria-labelledby="users-title">
        <?php render_nav(); ?>
        <div class="auth-heading">
            <p class="eyebrow">Admin</p>
            <h1 id="users-title">Manage users</h1>
            <p class="muted">Review accounts and update their roles.</p>
        </div>

        <?php if ($statusMessage !== null): ?>
            <div class="notice notice-success" role="status"><?= e($statusMessage) ?></div>
        <?php endif; ?>

        <?php if ($errors !== []): ?>
            <div class="notice notice-error" role="alert">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <div class="table-scroll">
            <table class="user-table">
                <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Last login</th>
                    <th>Change role</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td><?= e((string) $user['name']) ?></td>
                        <td><?= e((string) $user['email']) ?></td>
                        <td><?= e((string) $user['role']) ?></td>
                        <td><?= e((string) $user['created_at']) ?></td>
                        <td><?= e((string) ($user['last_login_at'] ?? 'Never')) ?></td>
                        <td>
                            <form class="role-form" method="post" action="users.php">
                                <?= csrf_field() ?>
                                <input type="hidden" name="user_id" value="<?= e((int) $user['id']) ?>">
                                <label class="visually-hidden" for="role-<?= e((int) $user['id']) ?>">
                                    Role for <?= e((string) $user['name']) ?>
                                </label>
                                <select id="role-<?= e((int) $user['id']) ?>" name="role">
                                    <option value="user"<?= $user['role'] === 'user' ? ' selected' : '' ?>>User</option>
                                    <option value="admin"<?= $user['role'] === 'admin' ? ' selected' : '' ?>>Admin</option>
                                </select>
                                <button type="submit"
                                    <?= (int) $user['id'] === (int) $admin['id'] && $user['role'] === 'admin' ? 'disabled' : '' ?>>
                                    Save
                                </button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($users === []): ?>
                    <tr><td colspan="6">No users found.</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>
</main>
</body>
</html>
