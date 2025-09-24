<?php
// dbcon.php

// FIX: Use PDO with exceptions, real prepared statements, and utf8mb4.
$DB_HOST = '127.0.0.1';
$DB_NAME = 'hospital';
$DB_USER = 'root';
$DB_PASS = ''; // Consider using environment variables or a secrets manager. // FIX: avoid hardcoding in production

$dsn = "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4";

try {
    $pdo = new PDO($dsn, $DB_USER, $DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // FIX: throw on errors
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false                   // FIX: real prepared statements (SQLi mitigation)
    ]);
} catch (PDOException $e) {
    // FIX: Do not reveal sensitive error details in production
    http_response_code(500);
    exit('Database connection error.');
}
