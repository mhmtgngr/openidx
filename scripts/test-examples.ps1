# OpenIDX Test Examples - PowerShell
# Run: .\scripts\test-examples.ps1

$BASE_URL = "http://localhost:8088"
$OAUTH_URL = "http://localhost:8006"

# Test client credentials (for API testing)
$CLIENT_ID = "test-client"
$CLIENT_SECRET = "test-secret"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "OpenIDX Test Examples" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ==========================================
# 1. Health Check
# ==========================================
Write-Host "1. Health Check" -ForegroundColor Yellow
Write-Host "-------------------------------------------"

try {
    $health = Invoke-RestMethod -Uri "$OAUTH_URL/.well-known/openid-configuration" -Method Get
    Write-Host "  [OK] OAuth service is healthy" -ForegroundColor Green
    Write-Host "  Issuer: $($health.issuer)"
} catch {
    Write-Host "  [FAIL] OAuth service is not responding" -ForegroundColor Red
}
Write-Host ""

# ==========================================
# 2. Get Access Token (Client Credentials)
# ==========================================
Write-Host "2. Getting Access Token (Client Credentials)" -ForegroundColor Yellow
Write-Host "-------------------------------------------"

$tokenBody = "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=openid"

try {
    $tokenResponse = Invoke-RestMethod -Uri "$OAUTH_URL/oauth/token" -Method Post -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
    $TOKEN = $tokenResponse.access_token
    Write-Host "  [OK] Got access token (service account)" -ForegroundColor Green
    Write-Host "  Token: $($TOKEN.Substring(0, [Math]::Min(50, $TOKEN.Length)))..."
} catch {
    Write-Host "  [FAIL] Failed to get token: $_" -ForegroundColor Red
}
Write-Host ""

# ==========================================
# 2b. Get User Token (via browser - manual step)
# ==========================================
Write-Host "2b. For User Token:" -ForegroundColor Yellow
Write-Host "-------------------------------------------"
Write-Host "  1. Open http://localhost:3000 in browser"
Write-Host "  2. Log in with admin@openidx.local / Admin123!"
Write-Host "  3. Open DevTools > Application > Local Storage"
Write-Host "  4. Copy the 'token' value"
Write-Host ""
Write-Host "  Or use this URL to start OAuth flow:"
Write-Host "  $OAUTH_URL/oauth/authorize?client_id=admin-console&response_type=code&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email"
Write-Host ""

# Ask user if they have a token
$userToken = Read-Host "Paste your user token (or press Enter to skip user tests)"
if ($userToken) {
    $TOKEN = $userToken
    Write-Host "  [OK] Using provided user token" -ForegroundColor Green
}
Write-Host ""

$headers = @{
    "Authorization" = "Bearer $TOKEN"
}

# ==========================================
# 3. Get Current User
# ==========================================
Write-Host "3. Get Current User Info" -ForegroundColor Yellow
Write-Host "-------------------------------------------"

try {
    $user = Invoke-RestMethod -Uri "$BASE_URL/api/v1/identity/users/me" -Headers $headers
    Write-Host "  [OK] Got user info" -ForegroundColor Green
    Write-Host "  Email: $($user.email)"
    Write-Host "  Name: $($user.first_name) $($user.last_name)"
} catch {
    Write-Host "  [FAIL] Failed to get user info" -ForegroundColor Red
}
Write-Host ""

# ==========================================
# 4. List Users
# ==========================================
Write-Host "4. List Users" -ForegroundColor Yellow
Write-Host "-------------------------------------------"

try {
    $users = Invoke-RestMethod -Uri "$BASE_URL/api/v1/identity/users?limit=5" -Headers $headers
    Write-Host "  [OK] Found $($users.total) users" -ForegroundColor Green
    foreach ($u in $users.users | Select-Object -First 3) {
        Write-Host "    - $($u.email)"
    }
} catch {
    Write-Host "  [FAIL] Failed to list users" -ForegroundColor Red
}
Write-Host ""

# ==========================================
# 5. Create Test User
# ==========================================
Write-Host "5. Create Test User" -ForegroundColor Yellow
Write-Host "-------------------------------------------"

$testEmail = "testuser_$(Get-Date -Format 'yyyyMMddHHmmss')@example.com"
$createBody = @{
    email = $testEmail
    first_name = "Test"
    last_name = "User"
    password = "TestUser123!"
} | ConvertTo-Json

try {
    $newUser = Invoke-RestMethod -Uri "$BASE_URL/api/v1/identity/users" -Method Post -Headers $headers -Body $createBody -ContentType "application/json"
    $testUserId = $newUser.id
    Write-Host "  [OK] Created user: $testEmail" -ForegroundColor Green
    Write-Host "  ID: $testUserId"
} catch {
    Write-Host "  [FAIL] Failed to create user: $_" -ForegroundColor Red
}
Write-Host ""

# ==========================================
# 6. List Groups
# ==========================================
Write-Host "6. List Groups" -ForegroundColor Yellow
Write-Host "-------------------------------------------"

try {
    $groups = Invoke-RestMethod -Uri "$BASE_URL/api/v1/identity/groups" -Headers $headers
    Write-Host "  [OK] Found $($groups.total) groups" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Failed to list groups" -ForegroundColor Red
}
Write-Host ""

# ==========================================
# 7. List Sessions
# ==========================================
Write-Host "7. List Active Sessions" -ForegroundColor Yellow
Write-Host "-------------------------------------------"

try {
    $sessions = Invoke-RestMethod -Uri "$BASE_URL/api/v1/sessions?active_only=true" -Headers $headers
    Write-Host "  [OK] Found $($sessions.total) active sessions" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Failed to list sessions" -ForegroundColor Red
}
Write-Host ""

# ==========================================
# 8. Get Audit Logs
# ==========================================
Write-Host "8. Get Recent Audit Logs" -ForegroundColor Yellow
Write-Host "-------------------------------------------"

try {
    $audit = Invoke-RestMethod -Uri "$BASE_URL/api/v1/audit/events?limit=5" -Headers $headers
    Write-Host "  [OK] Got audit logs" -ForegroundColor Green
    foreach ($event in $audit.events | Select-Object -First 3) {
        Write-Host "    - $($event.event_type): $($event.user_email)"
    }
} catch {
    Write-Host "  [FAIL] Failed to get audit logs" -ForegroundColor Red
}
Write-Host ""

# ==========================================
# 9. Cleanup
# ==========================================
Write-Host "9. Cleanup - Delete Test User" -ForegroundColor Yellow
Write-Host "-------------------------------------------"

if ($testUserId) {
    try {
        Invoke-RestMethod -Uri "$BASE_URL/api/v1/identity/users/$testUserId" -Method Delete -Headers $headers
        Write-Host "  [OK] Deleted test user" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Failed to delete test user" -ForegroundColor Red
    }
}
Write-Host ""

# ==========================================
# Summary
# ==========================================
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Test Complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Admin Console: http://localhost:3000"
Write-Host "API Base URL: $BASE_URL"
Write-Host "OAuth URL: $OAUTH_URL"
Write-Host ""
Write-Host "Your access token (valid for 1 hour):"
Write-Host $TOKEN
Write-Host ""
