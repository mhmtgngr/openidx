// Firebase configuration for the OpenIDX native client.
//
// Generated from the Android google-services.json for project "openidx-14ce9".
// The apiKey/appId here are CLIENT identifiers (they ship inside the APK) — not
// secrets — so embedding them is the standard FlutterFire approach.
//
// Android is configured. iOS is not yet: add a GoogleService-Info.plist and
// extend `currentPlatform` (or re-run `flutterfire configure`) to enable FCM on
// iOS. Until then iOS falls back to the ntfy transport. See
// docs/mobile/firebase-fcm-setup.md.
import 'package:firebase_core/firebase_core.dart' show FirebaseOptions;
import 'package:flutter/foundation.dart'
    show defaultTargetPlatform, kIsWeb, TargetPlatform;

class DefaultFirebaseOptions {
  static FirebaseOptions get currentPlatform {
    if (kIsWeb) {
      throw UnsupportedError(
          'Firebase web is not configured; push-MFA uses the ntfy fallback.');
    }
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
        return android;
      default:
        // iOS/macOS/other not configured yet → caller degrades to ntfy.
        throw UnsupportedError(
            'Firebase is not configured for $defaultTargetPlatform; push-MFA '
            'uses the ntfy fallback until a config is added.');
    }
  }

  static const FirebaseOptions android = FirebaseOptions(
    apiKey: 'AIzaSyC4O7IwB8ZEtKcWL2l2XcDGaFa_UxWo3ug',
    appId: '1:609475994536:android:554bd2a34de403927a339d',
    messagingSenderId: '609475994536',
    projectId: 'openidx-14ce9',
    storageBucket: 'openidx-14ce9.firebasestorage.app',
  );
}
