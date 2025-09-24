<?php
// update.php
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
function ensure_csrf_token() {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
}
function check_csrf_token($token) {
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token ?? '');
}
ensure_csrf_token();

$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

// Fetch record
$stmt = $pdo->prepare('SELECT * FROM appointment WHERE id = ? LIMIT 1'); // FIX: prepared
$stmt->execute([$id]);
$record = $stmt->fetch();

if (!$record) {
    http_response_code(404);
    exit('Appointment not found.');
}

$update_error = '';
$update_success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // FIX: CSRF check
    if (!check_csrf_token($_POST['csrf'] ?? '')) {
        $update_error = 'Invalid request.';
    } else {
        $name = trim($_POST['name'] ?? '');
        $surname = trim($_POST['surname'] ?? '');
        $id_number = trim($_POST['id_number'] ?? '');
        $city = trim($_POST['city'] ?? '');
        $department = trim($_POST['department'] ?? '');
        $date = trim($_POST['date'] ?? '');

        if ($name === '' || $surname === '' || $id_number === '' || $city === '' || $department === '' || $date === '') {
            $update_error = 'All fields are required.';
        } else {
            $d = DateTime::createFromFormat('Y-m-d', $date);
            if (!$d || $d->format('Y-m-d') !== $date) {
                $update_error = 'Invalid date (use YYYY-MM-DD).';
            } else {
                // FIX: prepared UPDATE
                $stmtU = $pdo->prepare('
                  UPDATE appointment
                  SET name = ?, surname = ?, id_number = ?, city = ?, department = ?, date = ?
                  WHERE id = ?
                ');
                $stmtU->execute([$name, $surname, $id_number, $city, $department, $date, $id]);
                $update_success = 'Appointment updated.';
                // Refresh $record to show updated values
                $stmt->execute([$id]);
                $record = $stmt->fetch();
            }
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Update Appointment</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>

<h1>Update Appointment #<?php echo (int)$record['id']; ?></h1>
<p><a href="home.php">Back</a></p>

<?php if ($update_error): ?>
  <div class="error"><?php echo htmlspecialchars($update_error, ENT_QUOTES, 'UTF-8'); // FIX: escape ?></div>
<?php elseif ($update_success): ?>
  <div class="success"><?php echo htmlspecialchars($update_success, ENT_QUOTES, 'UTF-8'); // FIX: escape ?></div>
<?php endif; ?>

<form method="post" action="update.php?id=<?php echo (int)$record['id']; ?>" autocomplete="off">
  <!-- FIX: CSRF token -->
  <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8'); ?>">

  <div><label>Name <input name="name" required value="<?php echo htmlspecialchars($record['name'], ENT_QUOTES, 'UTF-8'); // FIX: escape ?>"></label></div>
  <div><label>Surname <input name="surname" required value="<?php echo htmlspecialchars($record['surname'], ENT_QUOTES, 'UTF-8'); ?>"></label></div>
  <div><label>ID Number <input name="id_number" required value="<?php echo htmlspecialchars($record['id_number'], ENT_QUOTES, 'UTF-8'); ?>"></label></div>
  <div><label>City <input name="city" required value="<?php echo htmlspecialchars($record['city'], ENT_QUOTES, 'UTF-8'); ?>"></label></div>
  <div><label>Department <input name="department" required value="<?php echo htmlspecialchars($record['department'], ENT_QUOTES, 'UTF-8'); ?>"></label></div>
  <div><label>Date <input type="date" name="date" required value="<?php echo htmlspecialchars($record['date'], ENT_QUOTES, 'UTF-8'); ?>"></label></div>

  <button type="submit">Save</button>
</form>

</body>
</html>
