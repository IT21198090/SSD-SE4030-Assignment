<?php
// home.php
require __DIR__ . '/dbcon.php';

// ---- Session hardening (same as login) ----
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => $https,     // FIX: secure cookie
    'httponly' => true,       // FIX: httponly
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

$create_error = '';
$create_success = '';

// Handle CREATE (new appointment)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create') {
    // FIX: CSRF check
    if (!check_csrf_token($_POST['csrf'] ?? '')) {
        $create_error = 'Invalid request.';
    } else {
        // Basic validation
        $name = trim($_POST['name'] ?? '');
        $surname = trim($_POST['surname'] ?? '');
        $id_number = trim($_POST['id_number'] ?? '');
        $city = trim($_POST['city'] ?? '');
        $department = trim($_POST['department'] ?? '');
        $date = trim($_POST['date'] ?? '');

        if ($name === '' || $surname === '' || $id_number === '' || $city === '' || $department === '' || $date === '') {
            $create_error = 'All fields are required.';
        } else {
            // FIX: Validate date format (YYYY-MM-DD)
            $d = DateTime::createFromFormat('Y-m-d', $date);
            if (!$d || $d->format('Y-m-d') !== $date) {
                $create_error = 'Invalid date (use YYYY-MM-DD).';
            } else {
                // FIX: Prepared statement to prevent SQL injection
                $stmt = $pdo->prepare('
                    INSERT INTO appointment (name, surname, id_number, city, department, date)
                    VALUES (?, ?, ?, ?, ?, ?)
                ');
                $stmt->execute([$name, $surname, $id_number, $city, $department, $date]);
                $create_success = 'Appointment created.';
            }
        }
    }
}

// Fetch all appointments (you can add pagination later)
$rows = $pdo->query('SELECT id, name, surname, id_number, city, department, date, created_at FROM appointment ORDER BY id DESC')->fetchAll();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Control Panel - Hospital Appointment System</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>

<h1>Control Panel</h1>
<p>Welcome, <?php echo htmlspecialchars($_SESSION['user_name'], ENT_QUOTES, 'UTF-8'); // FIX: escape output ?></p>
<p><a href="logout.php">Logout</a></p>

<h2>Create Appointment</h2>

<?php if ($create_error): ?>
  <div class="error"><?php echo htmlspecialchars($create_error, ENT_QUOTES, 'UTF-8'); // FIX: escape ?></div>
<?php elseif ($create_success): ?>
  <div class="success"><?php echo htmlspecialchars($create_success, ENT_QUOTES, 'UTF-8'); // FIX: escape ?></div>
<?php endif; ?>

<form method="post" action="home.php" autocomplete="off">
  <!-- FIX: CSRF token -->
  <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8'); ?>">
  <input type="hidden" name="action" value="create">

  <div><label>Name <input name="name" required></label></div>
  <div><label>Surname <input name="surname" required></label></div>
  <div><label>ID Number <input name="id_number" required></label></div>
  <div><label>City <input name="city" required></label></div>
  <div><label>Department <input name="department" required></label></div>
  <div><label>Date <input type="date" name="date" required></label></div>
  <button type="submit">Add</button>
</form>

<h2>Appointments</h2>
<table border="1" cellpadding="6" cellspacing="0">
  <thead>
    <tr>
      <th>ID</th><th>Name</th><th>Surname</th><th>ID No</th><th>City</th><th>Department</th><th>Date</th><th>Actions</th>
    </tr>
  </thead>
  <tbody>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td><?php echo (int)$r['id']; ?></td>
        <td><?php echo htmlspecialchars($r['name'], ENT_QUOTES, 'UTF-8');   // FIX: escape ?></td>
        <td><?php echo htmlspecialchars($r['surname'], ENT_QUOTES, 'UTF-8'); // FIX: escape ?></td>
        <td><?php echo htmlspecialchars($r['id_number'], ENT_QUOTES, 'UTF-8'); // FIX: escape ?></td>
        <td><?php echo htmlspecialchars($r['city'], ENT_QUOTES, 'UTF-8');     // FIX: escape ?></td>
        <td><?php echo htmlspecialchars($r['department'], ENT_QUOTES, 'UTF-8'); // FIX: escape ?></td>
        <td><?php echo htmlspecialchars($r['date'], ENT_QUOTES, 'UTF-8');     // FIX: escape ?></td>
        <td>
          <a href="update.php?id=<?php echo (int)$r['id']; ?>">UPDATE</a>
          <!-- FIX: Delete via POST + CSRF (not GET link) -->
          <form method="post" action="delete.php" style="display:inline" onsubmit="return confirm('Delete this appointment?');">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="id" value="<?php echo (int)$r['id']; ?>">
            <button type="submit">DELETE</button>
          </form>
        </td>
      </tr>
    <?php endforeach; ?>
  </tbody>
</table>

</body>
</html>
