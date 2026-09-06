import 'dart:io' show Platform;
import 'dart:math';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// The push token + platform used to register this phone as a push-MFA approver
/// (the FastPass convergence).
class PushToken {
  const PushToken({required this.token, required this.platform});

  /// The device token sent to the server as `device_token`.
  ///
  /// Always `ntfy:<stable-per-install-id>`. Delivery happens over the per-user
  /// ntfy topic the app already subscribes to
  /// (`internal/identity/pushmfa.go` publishes every challenge to it), so the
  /// token only has to exist and de-dup — it is never handed to a push
  /// provider. The `ntfy:` prefix is the server's signal to skip the FCM/APNs
  /// send for this device rather than fail it.
  final String token;

  /// "ios" or "android" — the server's accepted platform values.
  final String platform;
}

/// Resolves the push token used to register the enrolled phone as an approver.
///
/// There is exactly one client-side transport: the self-hosted **ntfy** topic.
/// The backend also carries a real FCM HTTP v1 / APNs sender
/// (`internal/identity/pushmfa_providers.go`) for operators who provision one,
/// but the client half — the Firebase SDK, a `google-services.json`, an
/// `AIza…` app id compiled into the binary — is deliberately not shipped.
/// Re-adding it is documented in `docs/mobile/push-mfa-delivery.md`; until
/// something produces a provider token there is no second branch here to take.
class PushTokenService {
  PushTokenService({
    FlutterSecureStorage? storage,
    String? Function()? platformResolver,
  })  : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            ),
        _platformResolver = platformResolver ?? _hostPlatform;

  final FlutterSecureStorage _storage;

  /// How the current platform is named. Injected by tests: `flutter test` runs
  /// on the desktop host, where the real resolver returns null and every
  /// assertion about the mobile branch would sit behind an `if` that never
  /// fires — a test that passes by not running.
  final String? Function() _platformResolver;

  static const _kSyntheticId = 'openidx.push_synthetic_id';

  /// Returns the push token for this device, or null on platforms that are not
  /// a push authenticator (desktop).
  Future<PushToken?> resolve() async {
    final platform = _platformResolver();
    if (platform == null) return null; // desktop / unsupported

    final synthetic = await _stableSyntheticId();
    return PushToken(token: 'ntfy:$synthetic', platform: platform);
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

  static String? _hostPlatform() {
    if (Platform.isAndroid) return 'android';
    if (Platform.isIOS) return 'ios';
    return null;
  }
}
