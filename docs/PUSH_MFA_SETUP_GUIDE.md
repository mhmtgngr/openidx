# Push MFA Configuration Guide

## Complete Setup for Firebase Cloud Messaging (FCM) and Apple Push Notifications (APNS)

This guide will walk you through setting up Push MFA for OpenIDX, including Firebase for Android/Web and APNS for iOS.

---

## Part 1: Firebase Cloud Messaging (FCM) Setup

### For Android and Web Push Notifications

### Step 1: Create Firebase Project

1. **Go to Firebase Console**:
   - Visit: https://console.firebase.google.com/
   - Sign in with your Google account

2. **Create New Project**:
   - Click "Add project" or "Create a project"
   - Enter project name: `openidx-push-mfa` (or your preferred name)
   - Click "Continue"

3. **Google Analytics** (optional):
   - Enable/disable Google Analytics (recommended: disable for simplicity)
   - Click "Create project"
   - Wait for project creation (takes ~30 seconds)
   - Click "Continue" when done

### Step 2: Add Apps to Firebase Project

#### For Android App:

1. **Add Android App**:
   - In Firebase Console, click the Android icon (⚙️)
   - Or go to Project Settings → Your apps → Add app

2. **Register App**:
   - **Android package name**: `com.openidx.app` (must match your app)
   - **App nickname** (optional): `OpenIDX Android`
   - **Debug signing certificate SHA-1** (optional, for testing)
   - Click "Register app"

3. **Download Config File**:
   - Download `google-services.json`
   - Place it in your Android project: `android/app/google-services.json`
   - Click "Next"

4. **Add Firebase SDK** (for React Native):
   ```bash
   npm install @react-native-firebase/app
   npm install @react-native-firebase/messaging
   cd android && ./gradlew clean && cd ..
   ```

5. **Skip remaining steps** in Firebase wizard (React Native handles it)
   - Click "Continue to console"

#### For Web App (PWA):

1. **Add Web App**:
   - In Firebase Console, click the Web icon (</>)
   - **App nickname**: `OpenIDX Web`
   - Check "Also set up Firebase Hosting" (optional)
   - Click "Register app"

2. **Copy Firebase Config**:
   ```javascript
   const firebaseConfig = {
     apiKey: "AIzaSyD...",
     authDomain: "openidx-push-mfa.firebaseapp.com",
     projectId: "openidx-push-mfa",
     storageBucket: "openidx-push-mfa.appspot.com",
     messagingSenderId: "123456789",
     appId: "1:123456789:web:abcdef123456"
   };
   ```
   - Save this config for your web app
   - Click "Continue to console"

### Step 3: Get Server Key (Most Important!)

1. **Go to Project Settings**:
   - Click the gear icon ⚙️ → Project settings
   - Click "Cloud Messaging" tab

2. **Enable Firebase Cloud Messaging API**:
   - If you see "Firebase Cloud Messaging API (V1) is required"
   - Click the link or go to: https://console.cloud.google.com/apis/library/fcm.googleapis.com
   - Click "Enable"
   - Wait for API to be enabled

3. **Get Server Key** (Legacy):
   - In "Cloud Messaging" tab, scroll down to "Cloud Messaging API (Legacy)"
   - Find **Server key**: `AAAA...` (starts with AAAA)
   - **COPY THIS KEY** - this is your `FCM_SERVER_KEY`
   - ⚠️ **IMPORTANT**: Keep this secret! Never commit to Git!

   Example:
   ```
   Server key: AAAAt8ZJxYw:APA91bF...very-long-key
   ```

4. **Alternative: Get Service Account JSON** (Recommended for Production):
   - Go to Project Settings → Service Accounts
   - Click "Generate new private key"
   - Download JSON file (e.g., `openidx-push-mfa-firebase-adminsdk.json`)
   - Use Firebase Admin SDK in Go instead of legacy server key

### Step 4: Test FCM Setup

**Using curl**:
```bash
# Test sending push notification
curl -X POST https://fcm.googleapis.com/fcm/send \
  -H "Authorization: key=YOUR_SERVER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "DEVICE_TOKEN",
    "notification": {
      "title": "Test",
      "body": "Hello from OpenIDX"
    }
  }'
```

**Expected Response**:
```json
{
  "multicast_id": 123456789,
  "success": 1,
  "failure": 0
}
```

---

## Part 2: Apple Push Notification Service (APNS) Setup

### For iOS Push Notifications

### Step 1: Enroll in Apple Developer Program

1. **Join Apple Developer Program** (if not already):
   - Visit: https://developer.apple.com/programs/
   - Cost: $99/year
   - Complete enrollment process

2. **Sign in to Apple Developer**:
   - Visit: https://developer.apple.com/account/
   - Sign in with your Apple ID

### Step 2: Create App Identifier

1. **Go to Certificates, Identifiers & Profiles**:
   - https://developer.apple.com/account/resources/identifiers/list

2. **Create App ID**:
   - Click the "+" button
   - Select "App IDs" → "Continue"
   - Select "App" → "Continue"

3. **Register App ID**:
   - **Description**: `OpenIDX Push MFA`
   - **Bundle ID**: `com.openidx.app` (Explicit, must match your app)
   - **Capabilities**: Check ✅ "Push Notifications"
   - Click "Continue" → "Register"

### Step 3: Create APNs Authentication Key (Recommended)

**Option A: APNs Auth Key (Recommended - easier, works for all apps)**

1. **Create Key**:
   - Go to: https://developer.apple.com/account/resources/authkeys/list
   - Click the "+" button
   - **Key Name**: `OpenIDX APNS Key`
   - Check ✅ "Apple Push Notifications service (APNs)"
   - Click "Continue" → "Register"

2. **Download Key**:
   - Click "Download"
   - **Save the .p8 file**: `AuthKey_ABCD123456.p8`
   - ⚠️ **IMPORTANT**: You can only download this ONCE! Keep it safe!
   - Note down:
     - **Key ID**: `ABCD123456` (shown on page)
     - **Team ID**: `TEAM123456` (shown in top-right corner of developer portal)

3. **File Location**:
   ```bash
   # Store securely on your server
   /etc/openidx/certs/AuthKey_ABCD123456.p8

   # Set proper permissions (readable only by app)
   chmod 600 /etc/openidx/certs/AuthKey_ABCD123456.p8
   chown openidx:openidx /etc/openidx/certs/AuthKey_ABCD123456.p8
   ```

**Option B: APNs Certificate (Legacy - more complex, per-app)**

<details>
<summary>Click to expand legacy certificate method</summary>

1. **Create Certificate Signing Request (CSR)**:
   ```bash
   # On macOS
   # Open Keychain Access → Certificate Assistant → Request a Certificate
   # Fill in:
   # - User Email: your@email.com
   # - Common Name: OpenIDX APNs
   # - Save to disk
   ```

2. **Create APNs Certificate**:
   - Go to: https://developer.apple.com/account/resources/certificates/list
   - Click "+" → "Apple Push Notification service SSL (Sandbox & Production)"
   - Select your App ID: `com.openidx.app`
   - Upload CSR file
   - Download certificate (.cer file)

3. **Convert to .p12**:
   ```bash
   # Import .cer into Keychain
   # Export as .p12 with password
   ```

**Note**: Auth Key (Option A) is much simpler and recommended.
</details>

### Step 4: Enable Push Notifications in Xcode

1. **Open Xcode Project**:
   ```bash
   cd ios
   open OpenIDX.xcworkspace
   ```

2. **Select Target**:
   - Click project name in left sidebar
   - Select target: `OpenIDX`
   - Go to "Signing & Capabilities" tab

3. **Add Push Notifications**:
   - Click "+ Capability"
   - Search for "Push Notifications"
   - Add it

4. **Add Background Modes**:
   - Click "+ Capability"
   - Search for "Background Modes"
   - Check ✅ "Remote notifications"

5. **Configure Signing**:
   - Select your Team
   - Bundle Identifier: `com.openidx.app`
   - Ensure Provisioning Profile is valid

### Step 5: Test APNS Setup

**Using APNs HTTP/2 API**:
```bash
# Test with curl (macOS/Linux)
curl -v \
  --header "apns-topic: com.openidx.app" \
  --header "apns-push-type: alert" \
  --header "authorization: bearer YOUR_JWT_TOKEN" \
  --data '{"aps":{"alert":"Test"}}' \
  --http2 \
  https://api.sandbox.push.apple.com/3/device/DEVICE_TOKEN
```

**Or use online tool**:
- https://pushtry.com/
- Upload your .p8 file
- Enter device token
- Send test notification

---

## Part 3: Configure OpenIDX

### Update Configuration File

Create or edit `configs/config.yaml`:

```yaml
# WebAuthn Configuration
webauthn:
  rp_id: "yourdomain.com"                    # Your domain (no protocol, no port)
  rp_origins:                                # Allowed origins (with protocol)
    - "https://yourdomain.com"
    - "https://app.yourdomain.com"
  timeout: 60                                # Seconds

# Push MFA Configuration
push_mfa:
  enabled: true

  # Firebase Cloud Messaging (Android/Web)
  fcm_server_key: "AAAAt8ZJxYw:APA91bF..."  # From Firebase Console → Cloud Messaging

  # Apple Push Notifications (iOS)
  apns_key_id: "ABCD123456"                  # Key ID from Apple Developer
  apns_team_id: "TEAM123456"                 # Team ID from Apple Developer
  apns_key_path: "/etc/openidx/certs/AuthKey_ABCD123456.p8"  # Path to .p8 file

  # Settings
  challenge_timeout: 60                      # Seconds before challenge expires
  auto_approve: false                        # NEVER true in production!
```

### Using Environment Variables (Recommended for Production)

```bash
# .env file or export in shell

# WebAuthn
export OPENIDX_WEBAUTHN_RP_ID="yourdomain.com"
export OPENIDX_WEBAUTHN_RP_ORIGINS="https://yourdomain.com,https://app.yourdomain.com"
export OPENIDX_WEBAUTHN_TIMEOUT=60

# Push MFA
export OPENIDX_PUSH_MFA_ENABLED=true
export OPENIDX_PUSH_MFA_FCM_SERVER_KEY="AAAAt8ZJxYw:APA91bF..."
export OPENIDX_PUSH_MFA_APNS_KEY_ID="ABCD123456"
export OPENIDX_PUSH_MFA_APNS_TEAM_ID="TEAM123456"
export OPENIDX_PUSH_MFA_APNS_KEY_PATH="/etc/openidx/certs/AuthKey_ABCD123456.p8"
export OPENIDX_PUSH_MFA_CHALLENGE_TIMEOUT=60
export OPENIDX_PUSH_MFA_AUTO_APPROVE=false
```

### Docker Secrets (Recommended for Kubernetes)

```yaml
# kubernetes/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: openidx-push-mfa-secrets
type: Opaque
stringData:
  fcm-server-key: "AAAAt8ZJxYw:APA91bF..."
  apns-key-id: "ABCD123456"
  apns-team-id: "TEAM123456"
---
apiVersion: v1
kind: Secret
metadata:
  name: openidx-apns-key
type: Opaque
data:
  AuthKey_ABCD123456.p8: |
    LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t...  # base64 encoded .p8 file
```

---

## Part 4: Implement Push Notifications in Mobile App

### React Native (iOS + Android)

#### Install Dependencies

```bash
npm install @react-native-firebase/app
npm install @react-native-firebase/messaging
```

#### iOS Setup

```bash
cd ios
pod install
cd ..
```

Add to `ios/OpenIDX/AppDelegate.mm`:
```objc
#import <UserNotifications/UserNotifications.h>
#import <Firebase.h>

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
  [FIRApp configure];  // Add this line

  // Request permission
  UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
  [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert |
                                           UNAuthorizationOptionSound |
                                           UNAuthorizationOptionBadge)
                        completionHandler:^(BOOL granted, NSError * _Nullable error) {
    if (granted) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [[UIApplication sharedApplication] registerForRemoteNotifications];
      });
    }
  }];

  // ... rest of code
}
```

#### Android Setup

Add to `android/app/build.gradle`:
```gradle
apply plugin: 'com.google.gms.google-services'  // Add at bottom
```

Add to `android/build.gradle`:
```gradle
buildscript {
  dependencies {
    classpath 'com.google.gms:google-services:4.3.15'  // Add this
  }
}
```

Ensure `google-services.json` is in `android/app/`.

#### React Native Code

```javascript
// App.js
import React, {useEffect} from 'react';
import messaging from '@react-native-firebase/messaging';
import {Alert, Platform} from 'react-native';

export default function App() {

  useEffect(() => {
    // Request permission
    async function requestPermission() {
      const authStatus = await messaging().requestPermission();
      const enabled =
        authStatus === messaging.AuthorizationStatus.AUTHORIZED ||
        authStatus === messaging.AuthorizationStatus.PROVISIONAL;

      if (enabled) {
        console.log('Authorization status:', authStatus);
        registerDevice();
      }
    }

    requestPermission();

    // Handle foreground messages
    const unsubscribe = messaging().onMessage(async remoteMessage => {
      handlePushNotification(remoteMessage);
    });

    // Handle background messages
    messaging().setBackgroundMessageHandler(async remoteMessage => {
      console.log('Message handled in background:', remoteMessage);
    });

    return unsubscribe;
  }, []);

  async function registerDevice() {
    try {
      // Get FCM token
      const token = await messaging().getToken();
      console.log('FCM Token:', token);

      // Register with OpenIDX backend
      const response = await fetch('https://api.yourdomain.com/api/v1/identity/mfa/push/register?user_id=USER_ID', {
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

      const result = await response.json();
      console.log('Device registered:', result);
    } catch (error) {
      console.error('Registration error:', error);
    }
  }

  function handlePushNotification(remoteMessage) {
    const {challenge_id, challenge_code, ip_address, location} = remoteMessage.data;

    Alert.alert(
      'Login Attempt',
      `Someone is trying to log in from ${location || ip_address}\n\nEnter code: ${challenge_code}`,
      [
        {
          text: 'Deny',
          style: 'destructive',
          onPress: () => respondToChallenge(challenge_id, challenge_code, false)
        },
        {
          text: 'Approve',
          style: 'default',
          onPress: () => respondToChallenge(challenge_id, challenge_code, true)
        }
      ],
      {cancelable: false}
    );
  }

  async function respondToChallenge(challengeId, challengeCode, approved) {
    try {
      const response = await fetch('https://api.yourdomain.com/api/v1/identity/mfa/push/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          challenge_id: challengeId,
          challenge_code: challengeCode,
          approved: approved
        })
      });

      const result = await response.json();
      console.log('Challenge response:', result);

      Alert.alert(
        'Success',
        approved ? 'Login approved!' : 'Login denied.',
        [{text: 'OK'}]
      );
    } catch (error) {
      console.error('Challenge response error:', error);
      Alert.alert('Error', 'Failed to respond to challenge');
    }
  }

  return (
    <View>
      {/* Your app UI */}
    </View>
  );
}
```

---

## Part 5: Testing

### Test FCM (Android/Web)

1. **Get Device Token**:
   - Run your React Native app
   - Check console for: `FCM Token: xxxxx`
   - Copy this token

2. **Register Device**:
   ```bash
   curl -X POST 'http://localhost:8001/api/v1/identity/mfa/push/register?user_id=550e8400-e29b-41d4-a716-446655440000' \
     -H 'Content-Type: application/json' \
     -d '{
       "device_token": "YOUR_FCM_TOKEN",
       "platform": "android",
       "device_name": "Test Device"
     }'
   ```

3. **Create Challenge** (this sends push notification):
   ```bash
   curl -X POST 'http://localhost:8001/api/v1/identity/mfa/push/challenge' \
     -H 'Content-Type: application/json' \
     -d '{
       "user_id": "550e8400-e29b-41d4-a716-446655440000",
       "ip_address": "192.168.1.100",
       "location": "San Francisco, CA"
     }'
   ```

4. **Check Phone**:
   - You should receive a push notification
   - Notification shows: "Login Attempt" with challenge code

5. **Respond to Challenge**:
   - Tap notification
   - App opens with alert
   - Tap "Approve" or "Deny"

### Test APNS (iOS)

Same steps as FCM, but:
- Device token will be APNS token (different format)
- Platform should be `"ios"`
- Must test on real device (simulator doesn't support push)

### Development Testing (Without Mobile App)

Enable auto-approve mode:

```yaml
# config.yaml - DEVELOPMENT ONLY!
push_mfa:
  auto_approve: true
```

This bypasses actual push notifications for testing the API flow.

---

## Part 6: Production Checklist

### Security

- [ ] **Never commit secrets to Git**
  ```bash
  # Add to .gitignore
  echo "*.p8" >> .gitignore
  echo "google-services.json" >> .gitignore
  echo "config.yaml" >> .gitignore
  ```

- [ ] **Use environment variables or secrets manager**
  - Kubernetes Secrets
  - AWS Secrets Manager
  - HashiCorp Vault
  - Azure Key Vault

- [ ] **Restrict file permissions**
  ```bash
  chmod 600 /etc/openidx/certs/AuthKey_*.p8
  chown openidx:openidx /etc/openidx/certs/AuthKey_*.p8
  ```

- [ ] **Set `auto_approve: false` in production**

### Firebase

- [ ] Enable Firebase Cloud Messaging API (V1)
- [ ] Set up notification channels (Android 8+)
- [ ] Configure FCM quota limits
- [ ] Set up Firebase Analytics (optional)

### Apple

- [ ] Use Production APNS endpoint (not sandbox)
- [ ] Validate App Store provisioning profile
- [ ] Test on multiple iOS devices
- [ ] Configure badge numbers appropriately

### Monitoring

- [ ] Log all push notification sends
- [ ] Monitor FCM/APNS failure rates
- [ ] Set up alerts for high failure rates
- [ ] Track challenge response times

---

## Troubleshooting

### FCM Issues

**"Auth Error: Invalid Server Key"**
- Double-check server key from Firebase Console
- Ensure you copied the full key (starts with `AAAA`)
- Try regenerating server key

**"Not Registered" or "Invalid Registration"**
- Device token expired (get new token)
- App was uninstalled/reinstalled
- Clear app data and re-register

**"MismatchSenderId"**
- `google-services.json` doesn't match server key
- Re-download `google-services.json` from Firebase Console

### APNS Issues

**"Bad Certificate"**
- .p8 file is corrupted or wrong
- Key ID or Team ID is incorrect
- Re-download .p8 file from Apple Developer

**"Unregistered" or "BadDeviceToken"**
- Device token is invalid or expired
- Ensure app is properly signed
- Test with different device

**"TooManyProviderTokenUpdates"**
- You're regenerating tokens too often
- Use same .p8 file, don't create new ones

---

## Summary

### What You Need:

**For Android/Web (FCM)**:
1. Firebase project created
2. `google-services.json` downloaded
3. FCM Server Key copied

**For iOS (APNS)**:
1. Apple Developer account ($99/year)
2. App ID created with Push Notifications enabled
3. APNs Auth Key (.p8 file) downloaded
4. Key ID and Team ID noted

**For OpenIDX**:
1. Config file updated with all keys
2. `.p8` file stored securely on server
3. Mobile app with push notification handlers

### Configuration Example:

```yaml
push_mfa:
  enabled: true
  fcm_server_key: "AAAAt8ZJxYw:APA91bF..."
  apns_key_id: "ABCD123456"
  apns_team_id: "TEAM123456"
  apns_key_path: "/etc/openidx/certs/AuthKey_ABCD123456.p8"
  challenge_timeout: 60
  auto_approve: false  # Production setting
```

You're now ready to use Push MFA! 🎉

---

**Need Help?**
- Firebase Documentation: https://firebase.google.com/docs/cloud-messaging
- Apple APNS Documentation: https://developer.apple.com/documentation/usernotifications
- OpenIDX MFA Guide: `/docs/MFA_IMPLEMENTATION_GUIDE.md`
