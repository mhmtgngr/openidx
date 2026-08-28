// Firebase configuration for the OpenIDX native client.
//
// Generated from google-services.json (Android) + GoogleService-Info.plist (iOS)
// for project "openidx-14ce9". The apiKey/appId values are CLIENT
// identifiers (they ship in the app binary) — not secrets — so embedding them is
// the standard FlutterFire approach. Regenerate with `flutterfire configure`.
// See docs/mobile/firebase-fcm-setup.md.
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
      case TargetPlatform.iOS:
        return ios;
      default:
        // macOS/other not configured → caller degrades to ntfy.
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

  static const FirebaseOptions ios = FirebaseOptions(
    apiKey: 'AIzaSyA6blbfckvR5_dxfO-uiA11Yl8gqvtOdHQ',
    appId: '1:609475994536:ios:5eaa161747eaeca47a339d',
    messagingSenderId: '609475994536',
    projectId: 'openidx-14ce9',
    storageBucket: 'openidx-14ce9.firebasestorage.app',
    iosBundleId: 'com.example.openidxClient',
  );
}
