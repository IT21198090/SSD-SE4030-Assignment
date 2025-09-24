<?php
// oauth_login.php
require __DIR__ . '/oauth_config.php';

// ---- Session (secure cookie params) ----
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'domain' => '',
    'secure' => $https, 'httponly' => true, 'samesite' => 'Lax'
]);
session_start();

// PKCE helpers
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// FIX: Generate state + PKCE verifier/challenge (prevents CSRF & authorization code injection)
$state         = bin2hex(random_bytes(16));                    // FIX
$codeVerifier  = base64url_encode(random_bytes(64));           // FIX
$codeChallenge = base64url_encode(hash('sha256', $codeVerifier, true)); // FIX

$_SESSION['oauth2_state']         = $state;        // FIX
$_SESSION['oauth2_code_verifier'] = $codeVerifier; // FIX

$params = [
    'response_type' => 'code',
    'client_id'     => $GOOGLE_CLIENT_ID,
    'redirect_uri'  => $GOOGLE_REDIRECT_URI,
    'scope'         => $GOOGLE_SCOPES,
    'state'         => $state,
    'code_challenge'        => $codeChallenge,     // FIX: PKCE S256
    'code_challenge_method' => 'S256',
    'access_type'  => 'online',                     // or 'offline' if you need refresh_token
    'prompt'       => 'select_account'              // optional UX tweak
];

$authUrl = $GOOGLE_AUTH_URL . '?' . http_build_query($params);
header('Location: ' . $authUrl);
exit;
