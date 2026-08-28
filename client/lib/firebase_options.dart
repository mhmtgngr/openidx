// GENERATED STUB — do not hand-edit.
//
// Replace this file by running `flutterfire configure` once a Firebase project
// exists (see docs/mobile/firebase-fcm-setup.md). That command regenerates this
// file with the real per-platform FirebaseOptions.
//
// Until then `currentPlatform` throws, [FirebasePush] catches it, Firebase stays
// unavailable, and push-MFA is delivered over the always-on ntfy transport. This
// keeps the app (and CI) building with no Firebase project configured.
import 'package:firebase_core/firebase_core.dart';

class DefaultFirebaseOptions {
  static FirebaseOptions get currentPlatform => throw UnsupportedError(
        'Firebase is not configured. Run `flutterfire configure` to generate '
        'lib/firebase_options.dart. Until then push-MFA uses the ntfy fallback.',
      );
}
