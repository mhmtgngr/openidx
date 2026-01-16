# OpenIDX MFA Implementation Guide

## Overview

OpenIDX now supports three types of Multi-Factor Authentication (MFA):
1. **TOTP (Time-based One-Time Password)** - Google Authenticator compatible
2. **WebAuthn / FIDO2** - Passwordless authentication with passkeys and security keys
3. **Push Notification MFA** - Mobile push notifications with number matching

This guide covers the implementation, API usage, and best practices for all three methods.

---

## Table of Contents

- [WebAuthn (Passwordless Authentication)](#webauthn-passwordless-authentication)
- [Push Notification MFA](#push-notification-mfa)
- [TOTP MFA](#totp-mfa)
- [Frontend Integration Examples](#frontend-integration-examples)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

---

## WebAuthn (Passwordless Authentication)

### What is WebAuthn?

WebAuthn is a modern web standard that enables passwordless authentication using:
- **Passkeys** (synced across devices via iCloud, Google Password Manager)
- **Security Keys** (YubiKey, Titan Security Key)
- **Biometrics** (Touch ID, Face ID, Windows Hello)
- **Platform Authenticators** (device-bound credentials)

### Database Schema

```sql
CREATE TABLE mfa_webauthn (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,        -- Base64URL encoded
    public_key TEXT NOT NULL,                  -- COSE encoded
    sign_count BIGINT DEFAULT 0,               -- Replay attack prevention
    aaguid VARCHAR(36),                        -- Authenticator GUID
    transports TEXT[],                         -- usb, nfc, ble, internal
    name VARCHAR(255),                         -- User-friendly name
    backup_eligible BOOLEAN DEFAULT false,     -- Can be backed up
    backup_state BOOLEAN DEFAULT false,        -- Currently backed up
    attestation_format VARCHAR(50),            -- packed, fido-u2f, none
    created_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE
);
```

### API Endpoints

#### 1. Begin Registration

**Endpoint**: `POST /api/v1/identity/mfa/webauthn/register/begin`

**Request**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**: Returns WebAuthn PublicKeyCredentialCreationOptions
```json
{
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "rp": {
      "name": "OpenIDX",
      "id": "example.com"
    },
    "user": {
      "id": "base64url-encoded-user-id",
      "name": "john@example.com",
      "displayName": "John Doe"
    },
    "pubKeyCredParams": [
      {"type": "public-key", "alg": -7},
      {"type": "public-key", "alg": -257}
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "residentKey": "preferred",
      "userVerification": "preferred"
    },
    "timeout": 60000,
    "attestation": "none"
  }
}
```

#### 2. Finish Registration

**Endpoint**: `POST /api/v1/identity/mfa/webauthn/register/finish?user_id=<uuid>&name=My+Phone`

**Request**: Raw WebAuthn PublicKeyCredential response from browser
```json
{
  "id": "credential-id",
  "rawId": "base64url-encoded-rawId",
  "response": {
    "clientDataJSON": "base64url-encoded-data",
    "attestationObject": "base64url-encoded-data"
  },
  "type": "public-key"
}
```

**Response**:
```json
{
  "id": "credential-uuid",
  "user_id": "user-uuid",
  "credential_id": "base64url-credential-id",
  "name": "My Phone",
  "backup_eligible": true,
  "backup_state": true,
  "created_at": "2026-01-16T10:30:00Z"
}
```

#### 3. Begin Authentication

**Endpoint**: `POST /api/v1/identity/mfa/webauthn/authenticate/begin`

**Request**:
```json
{
  "username": "john@example.com"
}
```

**Response**: Returns WebAuthn PublicKeyCredentialRequestOptions
```json
{
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "rpId": "example.com",
    "allowCredentials": [
      {
        "id": "base64url-encoded-credential-id",
        "type": "public-key",
        "transports": ["internal", "hybrid"]
      }
    ],
    "timeout": 60000,
    "userVerification": "preferred"
  }
}
```

#### 4. Finish Authentication

**Endpoint**: `POST /api/v1/identity/mfa/webauthn/authenticate/finish?username=john@example.com`

**Request**: Raw WebAuthn PublicKeyCredential response
```json
{
  "id": "credential-id",
  "rawId": "base64url-encoded-rawId",
  "response": {
    "clientDataJSON": "base64url-encoded-data",
    "authenticatorData": "base64url-encoded-data",
    "signature": "base64url-encoded-signature",
    "userHandle": "base64url-encoded-user-id"
  },
  "type": "public-key"
}
```

**Response**:
```json
{
  "authenticated": true,
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "method": "webauthn"
}
```

#### 5. List Credentials

**Endpoint**: `GET /api/v1/identity/mfa/webauthn/credentials?user_id=<uuid>`

**Response**:
```json
[
  {
    "id": "cred-uuid-1",
    "name": "iPhone 13",
    "backup_eligible": true,
    "backup_state": true,
    "created_at": "2026-01-10T08:00:00Z",
    "last_used_at": "2026-01-16T09:30:00Z"
  },
  {
    "id": "cred-uuid-2",
    "name": "YubiKey 5",
    "backup_eligible": false,
    "backup_state": false,
    "created_at": "2026-01-15T14:20:00Z",
    "last_used_at": null
  }
]
```

#### 6. Delete Credential

**Endpoint**: `DELETE /api/v1/identity/mfa/webauthn/credentials/:credential_id?user_id=<uuid>`

**Response**: 204 No Content

### Configuration

Add to `configs/config.yaml`:

```yaml
webauthn:
  rp_id: "example.com"              # Your domain (no protocol, no port)
  rp_origins:                       # Allowed origins
    - "https://example.com"
    - "https://app.example.com"
  timeout: 60                       # Timeout in seconds
```

Environment variables:
```bash
OPENIDX_WEBAUTHN_RP_ID=example.com
OPENIDX_WEBAUTHN_RP_ORIGINS=https://example.com,https://app.example.com
OPENIDX_WEBAUTHN_TIMEOUT=60
```

---

## Push Notification MFA

### What is Push MFA?

Push MFA sends a notification to the user's mobile device asking them to approve or deny a login attempt. It includes:
- **Number matching** - User must enter a 2-digit code shown on login screen
- **Context information** - IP address, location, browser, time
- **Anti-phishing** - Prevents automated approval attacks

### Database Schema

```sql
-- Registered devices
CREATE TABLE mfa_push_devices (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_token TEXT UNIQUE NOT NULL,     -- FCM/APNS token
    platform VARCHAR(20) NOT NULL,         -- ios, android, web
    device_name VARCHAR(255),              -- "iPhone 13", "Pixel 6"
    device_model VARCHAR(100),
    os_version VARCHAR(50),
    app_version VARCHAR(50),
    enabled BOOLEAN DEFAULT true,
    trusted BOOLEAN DEFAULT false,
    last_ip VARCHAR(45),
    created_at TIMESTAMP,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP
);

-- Active challenges
CREATE TABLE mfa_push_challenges (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    device_id UUID REFERENCES mfa_push_devices(id),
    challenge_code VARCHAR(10) NOT NULL,   -- "73" number matching
    status VARCHAR(20) DEFAULT 'pending',  -- pending, approved, denied, expired
    session_info JSONB,                    -- Login context
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    responded_at TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255)
);
```

### API Endpoints

#### 1. Register Device

**Endpoint**: `POST /api/v1/identity/mfa/push/register?user_id=<uuid>`

**Request**:
```json
{
  "device_token": "fcm-or-apns-token-from-mobile-app",
  "platform": "ios",
  "device_name": "iPhone 13 Pro",
  "device_model": "iPhone14,3",
  "os_version": "17.2.1",
  "app_version": "1.0.0"
}
```

**Response**:
```json
{
  "id": "device-uuid",
  "user_id": "user-uuid",
  "platform": "ios",
  "device_name": "iPhone 13 Pro",
  "enabled": true,
  "trusted": false,
  "created_at": "2026-01-16T10:30:00Z"
}
```

#### 2. List Devices

**Endpoint**: `GET /api/v1/identity/mfa/push/devices?user_id=<uuid>`

**Response**:
```json
[
  {
    "id": "device-uuid-1",
    "platform": "ios",
    "device_name": "iPhone 13 Pro",
    "enabled": true,
    "trusted": true,
    "last_used_at": "2026-01-16T09:30:00Z",
    "created_at": "2026-01-10T08:00:00Z"
  },
  {
    "id": "device-uuid-2",
    "platform": "android",
    "device_name": "Pixel 6",
    "enabled": true,
    "trusted": false,
    "last_used_at": null,
    "created_at": "2026-01-15T14:20:00Z"
  }
]
```

#### 3. Delete Device

**Endpoint**: `DELETE /api/v1/identity/mfa/push/devices/:device_id?user_id=<uuid>`

**Response**: 204 No Content

#### 4. Create Challenge (Send Push)

**Endpoint**: `POST /api/v1/identity/mfa/push/challenge`

**Request**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "location": "San Francisco, CA"
}
```

**Response**:
```json
{
  "challenge_id": "challenge-uuid",
  "expires_at": "2026-01-16T10:31:00Z",
  "status": "pending"
}
```

**Push Notification Sent to Device**:
```json
{
  "title": "Login Attempt",
  "body": "Approve login from San Francisco, CA? Enter code: 73",
  "data": {
    "challenge_id": "challenge-uuid",
    "challenge_code": "73",
    "ip_address": "192.168.1.100",
    "location": "San Francisco, CA",
    "expires_at": 1705401060
  }
}
```

#### 5. Verify Challenge (User Response)

**Endpoint**: `POST /api/v1/identity/mfa/push/verify`

**Request** (from mobile app):
```json
{
  "challenge_id": "challenge-uuid",
  "challenge_code": "73",
  "approved": true
}
```

**Response**:
```json
{
  "verified": true,
  "method": "push_mfa"
}
```

#### 6. Check Challenge Status

**Endpoint**: `GET /api/v1/identity/mfa/push/challenge/:challenge_id`

**Response**:
```json
{
  "id": "challenge-uuid",
  "user_id": "user-uuid",
  "status": "approved",
  "created_at": "2026-01-16T10:30:00Z",
  "expires_at": "2026-01-16T10:31:00Z",
  "responded_at": "2026-01-16T10:30:15Z",
  "ip_address": "192.168.1.100",
  "location": "San Francisco, CA"
}
```

### Configuration

Add to `configs/config.yaml`:

```yaml
push_mfa:
  enabled: true
  fcm_server_key: "your-firebase-server-key"
  apns_key_id: "your-apns-key-id"
  apns_team_id: "your-apple-team-id"
  apns_key_path: "/path/to/AuthKey_XXXXX.p8"
  challenge_timeout: 60                 # Seconds
  auto_approve: false                   # NEVER set true in production!
```

Environment variables:
```bash
OPENIDX_PUSH_MFA_ENABLED=true
OPENIDX_PUSH_MFA_FCM_SERVER_KEY=AIzaSy...
OPENIDX_PUSH_MFA_CHALLENGE_TIMEOUT=60
OPENIDX_PUSH_MFA_AUTO_APPROVE=false
```

### Push Notification Implementation

#### Firebase Cloud Messaging (Android/Web)

```go
// Install: go get firebase.google.com/go/v4
import "firebase.google.com/go/v4/messaging"

func (s *Service) sendFCMNotification(ctx context.Context, token string, payload map[string]interface{}) error {
    message := &messaging.Message{
        Token: token,
        Notification: &messaging.Notification{
            Title: "Login Attempt",
            Body: fmt.Sprintf("Enter code: %s", payload["challenge_code"]),
        },
        Data: convertToStringMap(payload),
    }

    _, err := s.fcmClient.Send(ctx, message)
    return err
}
```

#### Apple Push Notification Service (iOS)

```go
// Install: go get github.com/sideshow/apns2
import "github.com/sideshow/apns2"

func (s *Service) sendAPNSNotification(ctx context.Context, token string, payload map[string]interface{}) error {
    notification := &apns2.Notification{
        DeviceToken: token,
        Topic:       "com.openidx.app",
        Payload: map[string]interface{}{
            "aps": map[string]interface{}{
                "alert": map[string]string{
                    "title": "Login Attempt",
                    "body":  fmt.Sprintf("Enter code: %s", payload["challenge_code"]),
                },
                "sound": "default",
            },
            "data": payload,
        },
    }

    res, err := s.apnsClient.Push(notification)
    return err
}
```

---

## TOTP MFA

Already implemented. See existing documentation for TOTP endpoints.

### Quick Reference

- `POST /api/v1/identity/mfa/totp/setup` - Begin TOTP enrollment
- `POST /api/v1/identity/mfa/totp/enroll` - Complete enrollment
- `POST /api/v1/identity/mfa/totp/verify` - Verify TOTP code
- `GET /api/v1/identity/mfa/totp/status` - Check if enabled
- `DELETE /api/v1/identity/mfa/totp` - Disable TOTP

---

## Frontend Integration Examples

### WebAuthn Registration (Browser)

```javascript
async function registerPasskey(userId) {
  // 1. Begin registration
  const beginResponse = await fetch('/api/v1/identity/mfa/webauthn/register/begin', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user_id: userId})
  });

  const options = await beginResponse.json();

  // 2. Convert base64url to ArrayBuffer
  options.publicKey.challenge = base64urlDecode(options.publicKey.challenge);
  options.publicKey.user.id = base64urlDecode(options.publicKey.user.id);

  // 3. Call browser WebAuthn API
  const credential = await navigator.credentials.create(options);

  // 4. Convert ArrayBuffer to base64url
  const credentialJSON = {
    id: credential.id,
    rawId: base64urlEncode(credential.rawId),
    response: {
      clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
      attestationObject: base64urlEncode(credential.response.attestationObject)
    },
    type: credential.type
  };

  // 5. Finish registration
  const finishResponse = await fetch(
    `/api/v1/identity/mfa/webauthn/register/finish?user_id=${userId}&name=My%20Device`,
    {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(credentialJSON)
    }
  );

  const result = await finishResponse.json();
  console.log('Passkey registered:', result);
}

// Helper functions
function base64urlDecode(str) {
  return Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

function base64urlEncode(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
```

### WebAuthn Authentication (Browser)

```javascript
async function authenticateWithPasskey(username) {
  // 1. Begin authentication
  const beginResponse = await fetch('/api/v1/identity/mfa/webauthn/authenticate/begin', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username})
  });

  const options = await beginResponse.json();

  // 2. Convert base64url to ArrayBuffer
  options.publicKey.challenge = base64urlDecode(options.publicKey.challenge);
  options.publicKey.allowCredentials.forEach(cred => {
    cred.id = base64urlDecode(cred.id);
  });

  // 3. Call browser WebAuthn API
  const assertion = await navigator.credentials.get(options);

  // 4. Convert ArrayBuffer to base64url
  const assertionJSON = {
    id: assertion.id,
    rawId: base64urlEncode(assertion.rawId),
    response: {
      clientDataJSON: base64urlEncode(assertion.response.clientDataJSON),
      authenticatorData: base64urlEncode(assertion.response.authenticatorData),
      signature: base64urlEncode(assertion.response.signature),
      userHandle: assertion.response.userHandle ? base64urlEncode(assertion.response.userHandle) : null
    },
    type: assertion.type
  };

  // 5. Finish authentication
  const finishResponse = await fetch(
    `/api/v1/identity/mfa/webauthn/authenticate/finish?username=${username}`,
    {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(assertionJSON)
    }
  );

  const result = await finishResponse.json();
  console.log('Authenticated:', result);
  return result.user_id;
}
```

### Push MFA Mobile App (React Native)

```javascript
import messaging from '@react-native-firebase/messaging';
import {Alert} from 'react-native';

// 1. Register device token
async function registerPushDevice(userId) {
  const token = await messaging().getToken();

  await fetch('/api/v1/identity/mfa/push/register?user_id=' + userId, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      device_token: token,
      platform: Platform.OS, // 'ios' or 'android'
      device_name: await DeviceInfo.getDeviceName(),
      device_model: DeviceInfo.getModel(),
      os_version: DeviceInfo.getSystemVersion(),
      app_version: DeviceInfo.getVersion()
    })
  });
}

// 2. Handle incoming push notifications
messaging().onMessage(async remoteMessage => {
  const {challenge_id, challenge_code, ip_address, location} = remoteMessage.data;

  Alert.alert(
    'Login Attempt',
    `Approve login from ${location || ip_address}?\n\nEnter code: ${challenge_code}`,
    [
      {text: 'Deny', onPress: () => respondToChallenge(challenge_id, challenge_code, false)},
      {text: 'Approve', onPress: () => respondToChallenge(challenge_id, challenge_code, true)}
    ]
  );
});

// 3. Respond to challenge
async function respondToChallenge(challengeId, challengeCode, approved) {
  await fetch('/api/v1/identity/mfa/push/verify', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      challenge_id: challengeId,
      challenge_code: challengeCode,
      approved
    })
  });
}
```

---

## Security Best Practices

### WebAuthn

1. **Always use HTTPS** - WebAuthn only works on secure contexts
2. **Set proper RP ID** - Must match your domain (no subdomains unless configured)
3. **Verify attestation** - Check authenticator attestation in production
4. **Enforce user verification** - Require PIN/biometric for sensitive operations
5. **Monitor sign counter** - Detect credential cloning attacks
6. **Backup credentials** - Encourage users to register multiple authenticators

### Push MFA

1. **Number matching is critical** - Prevents automated approval attacks
2. **Show context** - Display IP, location, device in notifications
3. **Short expiry** - Keep challenge timeout under 60 seconds
4. **Rate limiting** - Prevent push notification spam
5. **Trusted devices** - Mark frequently-used devices as trusted
6. **Fallback method** - Always provide TOTP as backup

### General

1. **Never store secrets in plaintext** - Use hashing for backup codes, secure key storage
2. **Audit all MFA events** - Log enrollment, authentication, failures
3. **Grace period** - Give users 24 hours to set up MFA after enforcement
4. **Recovery codes** - Provide backup codes for account recovery
5. **User education** - Explain what each MFA method is and how to use it

---

## Troubleshooting

### WebAuthn Issues

**Error: "SecurityError: The operation is insecure"**
- Solution: Ensure you're using HTTPS (http://localhost is allowed for dev)

**Error: "NotAllowedError: The operation was cancelled"**
- Solution: User cancelled the prompt, or timeout expired

**Error: "InvalidStateError: The credential already exists"**
- Solution: Credential already registered for this user

**Error: "NotSupportedError: The user agent does not support public key credentials"**
- Solution: Browser doesn't support WebAuthn (update browser)

### Push MFA Issues

**Push notification not received**
- Check device token is valid
- Verify FCM/APNS credentials are correct
- Check device is online and has permission for notifications
- Check notification is not blocked by OS/app settings

**Challenge expired**
- Default timeout is 60 seconds
- Increase `challenge_timeout` in config if needed

**Number mismatch**
- Ensure frontend displays same number as sent in push
- Check for typos in user input

---

## Migration Guide

### From TOTP to WebAuthn

Users can gradually migrate:
1. Enroll WebAuthn credential
2. Test passwordless login
3. Optionally disable TOTP

### Adding Push MFA

For existing users:
1. Release mobile app with Push MFA support
2. Users register devices from app settings
3. System automatically sends push if device registered, fallback to TOTP

---

## API Rate Limits

To prevent abuse:

| Endpoint | Rate Limit |
|----------|------------|
| WebAuthn register/begin | 5/minute per user |
| WebAuthn authenticate/begin | 10/minute per IP |
| Push challenge create | 5/minute per user |
| Push verify | 10/minute per challenge |

---

## Testing

### WebAuthn Testing

Use Chrome DevTools WebAuthn virtual authenticator:
1. Open DevTools → More Tools → WebAuthn
2. Enable virtual authenticator environment
3. Add virtual authenticator (USB, Internal, BLE)
4. Test registration and authentication

### Push MFA Testing (Development)

Set `auto_approve: true` in config to bypass actual push notifications:
```yaml
push_mfa:
  auto_approve: true  # Development only!
```

This automatically approves all challenges after 2 seconds.

---

## Performance Considerations

### WebAuthn
- Credential verification is CPU-intensive (ECDSA signature verification)
- Cache JWKS keys to avoid repeated fetches
- Store session data in Redis, not memory

### Push MFA
- Use async job queue for sending notifications
- Batch multiple challenges to same device
- Clean up expired challenges regularly (cron job)

---

## Support

For questions or issues:
- GitHub Issues: https://github.com/mhmtgngr/openidx/issues
- Documentation: https://docs.openidx.io
- Email: support@openidx.io

---

**Last Updated**: January 16, 2026
**Version**: 1.0.0
