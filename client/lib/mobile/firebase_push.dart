import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';

import '../firebase_options.dart';

/// Firebase Cloud Messaging integration for push-MFA delivery.
///
/// This is deliberately fail-soft: everything is guarded so the app runs
/// perfectly well with **no Firebase project configured**. Until a
/// `google-services.json` / `GoogleService-Info.plist` is present,
/// [ensureInitialized] is a no-op and [fetchToken] returns null, so
/// [PushTokenService] falls back to the always-on ntfy transport. Once the
/// config files are dropped in (see docs/mobile/firebase-fcm-setup.md), the same
/// code path lights up real FCM/APNs with zero other changes.
class FirebasePush {
  FirebasePush._();

  static bool _initAttempted = false;
  static bool _available = false;

  /// Attempts to initialize the default Firebase app. Safe to call repeatedly;
  /// only the first call does work. Never throws — a missing/invalid config
  /// simply leaves Firebase unavailable and the caller degrades to ntfy.
  static Future<void> ensureInitialized() async {
    if (_initAttempted) return;
    _initAttempted = true;
    try {
      // Uses the FlutterFire-generated options (lib/firebase_options.dart). The
      // committed STUB throws UnsupportedError → caught → stays unavailable, so
      // no native google-services.json/plist is needed to build. After
      // `flutterfire configure`, the real options light up FCM/APNs.
      await Firebase.initializeApp(
          options: DefaultFirebaseOptions.currentPlatform);
      _available = true;
    } catch (_) {
      _available = false;
    }
  }

  /// True once a Firebase app has been successfully initialized.
  static bool get available => _available;

  /// Returns the device's FCM registration token, or null when Firebase is not
  /// configured / permission is denied / any error occurs. Requests
  /// notification permission on first use (iOS/Android 13+).
  static Future<String?> fetchToken() async {
    await ensureInitialized();
    if (!_available) return null;
    try {
      final messaging = FirebaseMessaging.instance;
      await messaging.requestPermission();
      final token = await messaging.getToken();
      if (token == null || token.trim().isEmpty) return null;
      return token.trim();
    } catch (_) {
      return null;
    }
  }
}
