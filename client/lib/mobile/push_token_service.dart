import 'dart:io' show Platform;
import 'dart:math';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// The push token + platform used to register this phone as a push-MFA approver
/// (the FastPass convergence). [transport] records how challenges will actually
/// reach the device.
class PushToken {
  const PushToken({
    required this.token,
    required this.platform,
    required this.transport,
  });

  /// The device token sent to the server as `device_token`. For [Transport.fcm]
  /// this is the real FCM/APNs token; for [Transport.ntfy] it is a stable
  /// synthetic id (delivery happens over the per-user ntfy topic the app already
  /// subscribes to, so the token only needs to exist and de-dup).
  final String token;

  /// "ios" or "android" — the server's accepted platform values.
  final String platform;

  final Transport transport;
}

enum Transport { fcm, ntfy }

/// Resolves the push token used to register the enrolled phone as an approver.
///
/// Delivery has two transports. The real one is FCM (Android/Web) / APNs (iOS),
/// which requires a provisioned Firebase project + `firebase_messaging`. Until
/// that exists, we fall back to the always-on self-hosted **ntfy** path: the
/// backend delivers push-MFA prompts to a per-user ntfy topic regardless of the
/// device token, so a registered device with a stable synthetic token is enough
/// to make the convergence work end-to-end today.
///
/// When Firebase is provisioned, add `firebase_messaging` and set
/// [firebaseTokenFetcher] (or replace [resolve]'s FCM branch) to return the real
/// token with [Transport.fcm]; the rest of the pipeline is unchanged.
class PushTokenService {
  PushTokenService({
    FlutterSecureStorage? storage,
    Future<String?> Function()? firebaseTokenFetcher,
  })  : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            ),
        _firebaseTokenFetcher = firebaseTokenFetcher;

  final FlutterSecureStorage _storage;

  /// Optional hook returning a real FCM/APNs token. Null (the default) means no
  /// Firebase is wired, so we use the ntfy fallback. Injected in tests.
  final Future<String?> Function()? _firebaseTokenFetcher;

  static const _kSyntheticId = 'openidx.push_synthetic_id';

  /// Returns the push token for this device, or null on platforms that are not a
  /// push authenticator (desktop). Never throws: a Firebase failure degrades to
  /// the ntfy fallback so enrollment-time registration is best-effort.
  Future<PushToken?> resolve() async {
    final platform = _platform();
    if (platform == null) return null; // desktop / unsupported

    // Preferred: a real FCM/APNs token when Firebase is wired.
    if (_firebaseTokenFetcher != null) {
      try {
        final t = await _firebaseTokenFetcher!();
        if (t != null && t.trim().isNotEmpty) {
          return PushToken(
              token: t.trim(), platform: platform, transport: Transport.fcm);
        }
      } catch (_) {
        // Fall through to ntfy — never let a Firebase hiccup block enrollment.
      }
    }

    // Fallback: stable synthetic id, delivery over the per-user ntfy topic.
    final synthetic = await _stableSyntheticId();
    return PushToken(
        token: 'ntfy:$synthetic',
        platform: platform,
        transport: Transport.ntfy);
  }

  /// A stable, per-install id so re-enrolling the same phone updates its device
  /// row in place rather than creating duplicates.
  Future<String> _stableSyntheticId() async {
    final existing = await _storage.read(key: _kSyntheticId);
    if (existing != null && existing.isNotEmpty) return existing;
    final id = _randomId();
    await _storage.write(key: _kSyntheticId, value: id);
    return id;
  }

  String _randomId() {
    final rnd = Random.secure();
    final bytes = List<int>.generate(16, (_) => rnd.nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  String? _platform() {
    if (Platform.isAndroid) return 'android';
    if (Platform.isIOS) return 'ios';
    return null;
  }
}
