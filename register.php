<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$errors = [];
$name = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedToken = $_POST['_csrf_token'] ?? null;
    if (!csrf_verify(is_string($postedToken) ? $postedToken : null)) {
        http_response_code(419);
        $errors[] = 'Your form session expired. Reload the page and try again.';
    } else {
        $nameInput = $_POST['name'] ?? '';
        $emailInput = $_POST['email'] ?? '';
        $passwordInput = $_POST['password'] ?? '';
        $confirmationInput = $_POST['password_confirmation'] ?? '';

        $name = is_string($nameInput) ? trim($nameInput) : '';
        $email = is_string($emailInput) ? trim($emailInput) : '';
        $password = is_string($passwordInput) ? $passwordInput : '';
        $confirmation = is_string($confirmationInput) ? $confirmationInput : '';

        $_SESSION['_old'] = ['name' => $name, 'email' => $email];

        if ($name === '' || mb_strlen($name) > 100) {
            $errors[] = 'Enter a name no longer than 100 characters.';
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 254) {
            $errors[] = 'Enter a valid email address.';
        }

        if (strlen($password) < 10 || !preg_match('/[A-Za-z]/', $password) || !preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must be at least 10 characters and contain at least one letter and one number.';
        }

        if ($password !== $confirmation) {
            $errors[] = 'The password confirmation does not match.';
        }

        if ($errors === []) {
            $statement = db()->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
            $statement->execute(['email' => $email]);

            if ($statement->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            } else {
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                $insert = db()->prepare(
                    'INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)'
                );

                try {
                    $insert->execute([
                        'name' => $name,
                        'email' => $email,
                        'password_hash' => $passwordHash,
                    ]);
                } catch (PDOException $exception) {
                    if ($exception->getCode() !== '23000' || (int) ($exception->errorInfo[1] ?? 0) !== 1062) {
                        throw $exception;
                    }

                    $errors[] = 'An account with that email address already exists.';
                }

                if ($errors === []) {
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = (int) db()->lastInsertId();
                    $_SESSION['user_name'] = $name;
                    unset($_SESSION['_old'], $_SESSION['_csrf_token']);
                    redirect('dashboard.php');
                }
            }
        }
    }
}

if ($errors !== []) {
    $_SESSION['_old'] = ['name' => $name, 'email' => $email];
}

$name = old('name');
$email = old('email');
unset($_SESSION['_old']);
$successMessage = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Create account</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="register-title">
        <div class="auth-heading">
            <p class="eyebrow">Get started</p>
            <h1 id="register-title">Create your account</h1>
            <p class="muted">Enter your details to get started.</p>
        </div>

        <?php if ($successMessage !== null): ?>
            <div class="notice notice-success" role="status"><?= e($successMessage) ?></div>
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

        <form method="post" action="register.php" autocomplete="on">
            <?= csrf_field() ?>
            <label for="name">Name</label>
            <input id="name" name="name" type="text" maxlength="100" autocomplete="name" required
                   value="<?= e($name) ?>">

            <label for="email">Email</label>
            <input id="email" name="email" type="email" maxlength="254" autocomplete="email" required
                   value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" minlength="10" autocomplete="new-password" required>
            <small>At least 10 characters, including a letter and a number.</small>

            <label for="password_confirmation">Confirm password</label>
            <input id="password_confirmation" name="password_confirmation" type="password"
                   minlength="10" autocomplete="new-password" required>

            <button type="submit">Create account</button>
        </form>

        <p class="security-note">Your password is securely hashed before it is stored.</p>
    </section>
</main>
</body>
</html>
