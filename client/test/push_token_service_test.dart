import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/mobile/push_token_service.dart';

/// Verifies [PushTokenService]: an enrolled phone registers with a stable
/// `ntfy:` synthetic token, and a desktop host registers nothing.
///
/// The platform resolver is injected so the mobile branch actually runs here.
/// The previous version of this file wrapped every assertion in
/// `if (tok != null)`, and because `flutter test` runs on the desktop host that
/// condition was always false — three green tests that asserted nothing.
///
/// > Runs in CI via `.github/workflows/client-mobile-build.yml` and
/// > `client-desktop-build.yml` (`flutter test`).
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
      final key = call.arguments['key'] as String;
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

  PushTokenService mobile(String platform) =>
      PushTokenService(platformResolver: () => platform);

  test('registers an ntfy synthetic token on Android', () async {
    final tok = await mobile('android').resolve();
    expect(tok, isNotNull);
    expect(tok!.platform, 'android');
    expect(tok.token, startsWith('ntfy:'));
    // 16 random bytes, hex-encoded, after the prefix.
    expect(tok.token.substring('ntfy:'.length), matches(RegExp(r'^[0-9a-f]{32}$')));
  });

  test('registers an ntfy synthetic token on iOS', () async {
    final tok = await mobile('ios').resolve();
    expect(tok, isNotNull);
    expect(tok!.platform, 'ios');
    expect(tok.token, startsWith('ntfy:'));
  });

  test('the synthetic id is stable across calls and instances', () async {
    final first = await mobile('android').resolve();
    final again = await mobile('android').resolve();
    // A fresh service instance must read the persisted id, not mint a new one:
    // re-enrolling the same phone updates its device row instead of adding one.
    final fresh = await mobile('android').resolve();

    expect(first!.token, again!.token);
    expect(first.token, fresh!.token);
  });

  test('a fresh install mints a new id rather than reusing a blank', () async {
    final first = await mobile('android').resolve();
    store.clear(); // uninstall / keychain wiped
    final second = await mobile('android').resolve();
    expect(second!.token, isNot(first!.token));
    expect(second.token, startsWith('ntfy:'));
  });

  test('desktop is not a push authenticator', () async {
    final svc = PushTokenService(platformResolver: () => null);
    expect(await svc.resolve(), isNull);
  });
}
