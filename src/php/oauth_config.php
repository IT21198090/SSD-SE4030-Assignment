<?php
// oauth_config.php
// FIX: Read secrets from environment variables (avoid hardcoding in repo)
$GOOGLE_CLIENT_ID     = getenv('GOOGLE_CLIENT_ID')     ?: 'YOUR_GOOGLE_CLIENT_ID';
$GOOGLE_CLIENT_SECRET = getenv('GOOGLE_CLIENT_SECRET') ?: 'YOUR_GOOGLE_CLIENT_SECRET';
$GOOGLE_REDIRECT_URI  = getenv('GOOGLE_REDIRECT_URI')  ?: 'https://yourdomain.com/oauth_callback.php';

// Google OAuth endpoints
$GOOGLE_AUTH_URL  = 'https://accounts.google.com/o/oauth2/v2/auth';
$GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
$GOOGLE_JWKS_URL  = 'https://www.googleapis.com/oauth2/v3/certs'; // for JWT verify (advanced)
$GOOGLE_TOKENINFO = 'https://oauth2.googleapis.com/tokeninfo';    // simple id_token verify endpoint
$GOOGLE_SCOPES    = 'openid email profile';
