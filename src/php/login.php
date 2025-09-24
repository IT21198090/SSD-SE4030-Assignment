<?php
// login.php
require __DIR__ . '/dbcon.php';

// ---- Session hardening ----
// FIX: Secure cookie params (set once, before session_start)
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',           // keep default
    'secure'   => $https,       // FIX: secure cookies over HTTPS
    'httponly' => true,         // FIX: mitigate XSS cookie theft
    'samesite' => 'Lax'         // FIX: basic CSRF mitigation for top-level navigation
]);
session_start();

// Simple CSRF helpers (no extra files needed)
function ensure_csrf_token() {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
}
function check_csrf_token($token) {
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token ?? '');
}
ensure_csrf_token();

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // FIX: CSRF protection on login form
    if (!check_csrf_token($_POST['csrf'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $name = trim($_POST['name'] ?? '');
        $pass = $_POST['password'] ?? '';

        if ($name === '' || $pass === '') {
            $error = 'Username and password are required.';
        } else {
            // FIX: Use prepared statement (prevents SQL injection)
            $stmt = $pdo->prepare('SELECT id, name, password_hash FROM users WHERE name = ? LIMIT 1');
            $stmt->execute([$name]);
            $user = $stmt->fetch();

            // FIX: verify hashed password (no plaintext)
            if ($user && password_verify($pass, $user['password_hash'])) {
                // FIX: session fixation defense
                session_regenerate_id(true);
                $_SESSION['user_id'] = (int)$user['id'];
                $_SESSION['user_name'] = $user['name'];
                header('Location: home.php');
                exit;
            } else {
                $error = 'Invalid credentials.'; // Do not reveal which field failed
            }
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Login - Hospital Appointment System</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <h1>Login</h1>

  <?php if ($error): ?>
    <div class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); // FIX: escape output (XSS) ?></div>
  <?php endif; ?>

  <form method="post" action="login.php" autocomplete="off">
    <!-- FIX: CSRF token -->
    <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8'); ?>">

    <div>
      <label>Username</label>
      <input type="text" name="name" required>
    </div>
    <div>
      <label>Password</label>
      <input type="password" name="password" required>
    </div>
    <button type="submit">Login</button>
  </form>

  <p>Tip: Create a user with a hashed password using a small one-time script:
  <code>
  &lt;?php require 'dbcon.php';
  $u='admin'; $p=password_hash('StrongP@ssw0rd', PASSWORD_BCRYPT);
  $pdo-&gt;prepare('INSERT INTO users(name,password_hash) VALUES(?,?)')-&gt;execute([$u,$p]); ?&gt;
  </code>
  </p>
</body>
</html>
