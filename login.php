<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

$errors = [];
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedToken = $_POST['_csrf_token'] ?? null;

    if (!csrf_verify(is_string($postedToken) ? $postedToken : null)) {
        http_response_code(419);
        $errors[] = 'Your form session expired. Reload the page and try again.';
    } else {
        $emailInput = $_POST['email'] ?? '';
        $passwordInput = $_POST['password'] ?? '';
        $email = is_string($emailInput) ? trim($emailInput) : '';
        $password = is_string($passwordInput) ? $passwordInput : '';
        $_SESSION['_old'] = ['email' => $email];

        $remoteAddress = $_SERVER['REMOTE_ADDR'] ?? '';
        $ipAddress = is_string($remoteAddress) && filter_var($remoteAddress, FILTER_VALIDATE_IP) !== false
            ? $remoteAddress
            : '0.0.0.0';
        $waitMinutes = login_throttle_minutes($email, $ipAddress);

        if ($waitMinutes !== null) {
            $errors[] = 'Too many attempts, try again in ' . $waitMinutes . ' minutes';
        } else {
            $statement = db()->prepare(
                'SELECT id, name, email, password_hash, role, session_version '
                . 'FROM users WHERE email = :email LIMIT 1'
            );
            $statement->execute(['email' => $email]);
            $user = $statement->fetch();

            if ($user === false || !password_verify($password, (string) $user['password_hash'])) {
                record_failed_login($email, $ipAddress);
                $errors[] = 'Invalid email or password';
            } else {
                $passwordHash = (string) $user['password_hash'];
                if (password_needs_rehash($passwordHash, PASSWORD_DEFAULT)) {
                    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                }

                $update = db()->prepare(
                    'UPDATE users SET password_hash = :password_hash, last_login_at = CURRENT_TIMESTAMP WHERE id = :id'
                );
                $update->execute([
                    'password_hash' => $passwordHash,
                    'id' => (int) $user['id'],
                ]);
                clear_login_attempts($email, $ipAddress);

                session_regenerate_id(true);
                $_SESSION['user_id'] = (int) $user['id'];
                $_SESSION['user_role'] = (string) $user['role'];
                $_SESSION['user_name'] = (string) $user['name'];
                $_SESSION['session_version'] = (int) $user['session_version'];
                $_SESSION['_last_activity'] = time();
                unset($_SESSION['_old'], $_SESSION['_csrf_token']);

                $intendedUrl = valid_intended_url($_SESSION['_intended_url'] ?? null);
                unset($_SESSION['_intended_url']);
                redirect($intendedUrl ?? 'dashboard.php');
            }
        }
    }
}

$email = old('email', $email);
unset($_SESSION['_old']);
$statusMessage = flash('status');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="login-title">
        <div class="auth-heading">
            <p class="eyebrow">Welcome back</p>
            <h1 id="login-title">Sign in</h1>
            <p class="muted">Use your email and password to access your account.</p>
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

        <form method="post" action="login.php" autocomplete="on">
            <?= csrf_field() ?>
            <label for="email">Email</label>
            <input id="email" name="email" type="email" maxlength="254" autocomplete="email" required
                   value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>

            <button type="submit">Sign in</button>
        </form>

        <p class="security-note">New here? <a href="register.php">Create an account</a></p>
    </section>
</main>
</body>
</html>
