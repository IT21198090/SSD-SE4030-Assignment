<?php
// oauth_callback.php
require __DIR__ . '/dbcon.php';
require __DIR__ . '/oauth_config.php';

// ---- Session (secure cookie params) ----
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'domain' => '',
    'secure' => $https, 'httponly' => true, 'samesite' => 'Lax'
]);
session_start();

// 1) CSRF check on 'state'   // FIX: prevent CSRF
if (empty($_GET['state']) || $_GET['state'] !== ($_SESSION['oauth2_state'] ?? null)) {
    http_response_code(400);
    exit('Invalid state.');
}
unset($_SESSION['oauth2_state']); // one-time use

if (empty($_GET['code'])) {
    http_response_code(400);
    exit('Missing authorization code.');
}

// 2) Exchange code for tokens (Auth Code + PKCE) // FIX: token request with code_verifier
$code = $_GET['code'];
$codeVerifier = $_SESSION['oauth2_code_verifier'] ?? '';
unset($_SESSION['oauth2_code_verifier']);

$post = [
    'grant_type'    => 'authorization_code',
    'code'          => $code,
    'redirect_uri'  => $GOOGLE_REDIRECT_URI,
    'client_id'     => $GOOGLE_CLIENT_ID,
    'code_verifier' => $codeVerifier
    // Note: In PKCE public clients, client_secret is not required.
];

$ch = curl_init($GOOGLE_TOKEN_URL);
curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
    CURLOPT_POSTFIELDS     => http_build_query($post)
]);
$resp = curl_exec($ch);
$http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
if ($resp === false || $http !== 200) {
    http_response_code(502);
    exit('Token exchange failed.');
}
$tokenData = json_decode($resp, true);
curl_close($ch);

// Expect id_token (JWT) and access_token
$idToken     = $tokenData['id_token']     ?? null;
$accessToken = $tokenData['access_token'] ?? null;
if (!$idToken) {
    http_response_code(502);
    exit('Missing id_token.');
}

// 3) Verify id_token (simple method via Google tokeninfo) // FIX: basic validation
$verifyUrl = $GOOGLE_TOKENINFO . '?id_token=' . urlencode($idToken);
$verify = json_decode(file_get_contents($verifyUrl), true);
if (empty($verify) || ($verify['aud'] ?? '') !== $GOOGLE_CLIENT_ID) {
    http_response_code(401);
    exit('Invalid id_token.');
}

// Pull profile fields
$googleSub  = $verify['sub']   ?? null; // stable unique id // FIX
$email      = $verify['email'] ?? null;
$name       = $verify['name']  ?? ($verify['given_name'] ?? 'google_user');

if (!$googleSub) {
    http_response_code(401);
    exit('Invalid Google profile.');
}

// 4) Find or create local user (no password needed for OAuth)
$stmt = $pdo->prepare('SELECT id, name FROM users WHERE provider = ? AND provider_sub = ? LIMIT 1'); // FIX: prepared
$stmt->execute(['google', $googleSub]);
$user = $stmt->fetch();

if (!$user) {
    // Optional: if you want to merge with existing local account by email, add that logic here (careful with takeover risks!)
    $insert = $pdo->prepare('INSERT INTO users (name, password_hash, provider, provider_sub) VALUES (?, ?, ?, ?)'); // FIX
    $randomPwdHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT); // placeholder
    $displayName = $name ?: ($email ?: ('user_' . substr($googleSub, -6)));
    $insert->execute([$displayName, $randomPwdHash, 'google', $googleSub]);

    $userId = (int)$pdo->lastInsertId();
    $user = ['id' => $userId, 'name' => $displayName];
}

// 5) Log user in (session fixation defense) // FIX
session_regenerate_id(true);
$_SESSION['user_id']   = (int)$user['id'];
$_SESSION['user_name'] = $user['name'];

// Done
header('Location: home.php');
exit;
