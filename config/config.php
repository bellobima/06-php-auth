<?php
declare(strict_types=1);

$configuredEnvironment = getenv('APP_ENV');
define('APP_ENV', $configuredEnvironment !== false ? $configuredEnvironment : 'production');

$httpsRequired = getenv('APP_REQUIRE_HTTPS');
define(
    'APP_REQUIRE_HTTPS',
    $httpsRequired === false ? APP_ENV !== 'development' : filter_var($httpsRequired, FILTER_VALIDATE_BOOLEAN)
);

const DB_HOST = '127.0.0.1';
const DB_PORT = '3306';
const DB_NAME = 'swd_auth';
const DB_USER = 'root';
const DB_PASS = '';
