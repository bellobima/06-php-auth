<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();
$errors = [];
$name = (string) $user['name'];
$email = (string) $user['email'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedToken = $_POST['_csrf_token'] ?? null;

    if (!csrf_verify(is_string($postedToken) ? $postedToken : null)) {
        http_response_code(419);
        $errors[] = 'Your form session expired. Reload the page and try again.';
    } else {
        $formInput = $_POST['form'] ?? null;
        $form = is_string($formInput) ? $formInput : '';

        if ($form === 'profile') {
            $nameInput = $_POST['name'] ?? '';
            $emailInput = $_POST['email'] ?? '';
            $name = is_string($nameInput) ? trim($nameInput) : '';
            $email = is_string($emailInput) ? trim($emailInput) : '';

            if ($name === '' || mb_strlen($name) > 100) {
                $errors[] = 'Enter a name no longer than 100 characters.';
            }

            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 254) {
                $errors[] = 'Enter a valid email address.';
            }

            if ($errors === []) {
                $update = db()->prepare('UPDATE users SET name = :name, email = :email WHERE id = :id');

                try {
                    $update->execute([
                        'name' => $name,
                        'email' => $email,
                        'id' => (int) $user['id'],
                    ]);
                } catch (PDOException $exception) {
                    if ($exception->getCode() !== '23000' || (int) ($exception->errorInfo[1] ?? 0) !== 1062) {
                        throw $exception;
                    }

                    $errors[] = 'An account with that email address already exists.';
                }

                if ($errors === []) {
                    $_SESSION['user_name'] = $name;
                    flash('status', 'Your profile has been updated.');
                    redirect('profile.php');
                }
            }
        } elseif ($form === 'password') {
            $currentPasswordInput = $_POST['current_password'] ?? '';
            $newPasswordInput = $_POST['new_password'] ?? '';
            $confirmationInput = $_POST['password_confirmation'] ?? '';
            $currentPassword = is_string($currentPasswordInput) ? $currentPasswordInput : '';
            $newPassword = is_string($newPasswordInput) ? $newPasswordInput : '';
            $confirmation = is_string($confirmationInput) ? $confirmationInput : '';

            $statement = db()->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
            $statement->execute(['id' => (int) $user['id']]);
            $storedHash = $statement->fetchColumn();

            if (!is_string($storedHash) || !password_verify($currentPassword, $storedHash)) {
                $errors[] = 'The current password is incorrect.';
            }

            if (strlen($newPassword) < 10
                || !preg_match('/[A-Za-z]/', $newPassword)
                || !preg_match('/[0-9]/', $newPassword)) {
                $errors[] = 'New password must be at least 10 characters and contain at least one letter and one number.';
            }

            if ($newPassword !== $confirmation) {
                $errors[] = 'The password confirmation does not match.';
            }

            if ($errors === []) {
                $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
                $update = db()->prepare(
                    'UPDATE users SET password_hash = :password_hash, session_version = session_version + 1 '
                    . 'WHERE id = :id'
                );
                $update->execute([
                    'password_hash' => $newHash,
                    'id' => (int) $user['id'],
                ]);

                $versionQuery = db()->prepare('SELECT session_version FROM users WHERE id = :id');
                $versionQuery->execute(['id' => (int) $user['id']]);
                $sessionVersion = $versionQuery->fetchColumn();
                if (!is_string($sessionVersion) && !is_int($sessionVersion)) {
                    throw new RuntimeException('Could not reload the account session version after changing password.');
                }

                $_SESSION['session_version'] = (int) $sessionVersion;
                session_regenerate_id(true);
                $_SESSION['_last_activity'] = time();
                unset($_SESSION['_csrf_token']);
                flash('status', 'Your password has been changed.');
                redirect('profile.php');
            }
        } else {
            http_response_code(400);
            $errors[] = 'Choose a valid profile action.';
        }
    }
}

$statusMessage = flash('status');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your profile</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="profile-title">
        <?php render_nav(); ?>
        <div class="auth-heading">
            <p class="eyebrow">Account settings</p>
            <h1 id="profile-title">Your profile</h1>
            <p class="muted">Update your account details and password.</p>
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

        <h2>Profile details</h2>
        <form method="post" action="profile.php" autocomplete="on">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="profile">
            <label for="name">Name</label>
            <input id="name" name="name" type="text" maxlength="100" autocomplete="name" required
                   value="<?= e($name) ?>">

            <label for="email">Email</label>
            <input id="email" name="email" type="email" maxlength="254" autocomplete="email" required
                   value="<?= e($email) ?>">

            <button type="submit">Save profile</button>
        </form>

        <h2>Change password</h2>
        <form method="post" action="profile.php" autocomplete="on">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="password">
            <label for="current_password">Current password</label>
            <input id="current_password" name="current_password" type="password"
                   autocomplete="current-password" required>

            <label for="new_password">New password</label>
            <input id="new_password" name="new_password" type="password" minlength="10"
                   autocomplete="new-password" required>
            <small>At least 10 characters, including a letter and a number.</small>

            <label for="password_confirmation">Confirm new password</label>
            <input id="password_confirmation" name="password_confirmation" type="password"
                   minlength="10" autocomplete="new-password" required>

            <button type="submit">Change password</button>
        </form>
    </section>
</main>
</body>
</html>
