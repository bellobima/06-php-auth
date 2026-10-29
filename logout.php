<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Method Not Allowed');
}

$postedToken = $_POST['_csrf_token'] ?? null;
if (!csrf_verify(is_string($postedToken) ? $postedToken : null)) {
    http_response_code(419);
    exit('Your form session expired. Reload the page and try again.');
}

end_session('You have been signed out.');
redirect('login.php');
