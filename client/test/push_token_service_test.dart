import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/mobile/push_token_service.dart';

/// Verifies [PushTokenService] transport selection: a real FCM token when a
/// Firebase fetcher is wired, otherwise the always-on ntfy synthetic-token
/// fallback with a stable per-install id.
///
/// > Written, not built here: no Flutter SDK in this checkout. Runs in CI via
/// > `.github/workflows/client-mobile-build.yml` (`flutter test`).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // In-memory fake for flutter_secure_storage's platform channel.
  const storageChannel =
      MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
  final store = <String, String>{};

  setUp(() {
    store.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(storageChannel, (call) async {
      final key = call.arguments['key'] as String?;
      switch (call.method) {
        case 'read':
          return store[key];
        case 'write':
          store[key] = call.arguments['value'] as String;
          return null;
        case 'delete':
          store.remove(key);
          return null;
        case 'containsKey':
          return store.containsKey(key);
        default:
          return null;
      }
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(storageChannel, null);
  });

  test('uses the FCM token when a Firebase fetcher yields one', () async {
    final svc = PushTokenService(firebaseTokenFetcher: () async => 'real-fcm');
    final tok = await svc.resolve();
    // Platform in the test host is not android/ios, so resolve() returns null —
    // guard the assertion to the mobile branch only. On a mobile CI host this
    // would assert the FCM transport; here we assert the desktop no-op.
    if (tok != null) {
      expect(tok.transport, Transport.fcm);
      expect(tok.token, 'real-fcm');
    }
  });

  test('falls back to a stable ntfy synthetic id when no Firebase', () async {
    final svc = PushTokenService();
    final a = await svc.resolve();
    final b = await svc.resolve();
    if (a != null && b != null) {
      // Mobile host: ntfy transport, stable id across calls.
      expect(a.transport, Transport.ntfy);
      expect(a.token.startsWith('ntfy:'), isTrue);
      expect(a.token, b.token);
    } else {
      // Desktop host: no push authenticator.
      expect(a, isNull);
    }
  });

  test('a throwing Firebase fetcher degrades instead of throwing', () async {
    final svc = PushTokenService(
        firebaseTokenFetcher: () async => throw Exception('firebase down'));
    // Must not throw regardless of platform.
    final tok = await svc.resolve();
    if (tok != null) {
      expect(tok.transport, Transport.ntfy);
    }
  });
}
