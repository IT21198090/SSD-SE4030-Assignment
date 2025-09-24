<?php
// delete.php
require __DIR__ . '/dbcon.php';

// ---- Session hardening ----
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => $https,
    'httponly' => true,
    'samesite' => 'Lax'
]);
session_start();

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// CSRF helpers
function check_csrf_token($token) {
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token ?? '');
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method Not Allowed');
}

if (!check_csrf_token($_POST['csrf'] ?? '')) { // FIX: CSRF check
    http_response_code(400);
    exit('Invalid request.');
}

$id = isset($_POST['id']) ? (int)$_POST['id'] : 0;

if ($id > 0) {
    // FIX: prepared DELETE
    $stmt = $pdo->prepare('DELETE FROM appointment WHERE id = ?');
    $stmt->execute([$id]);
}

header('Location: home.php');
exit;
