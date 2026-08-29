import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/mobile/app_lock.dart';

/// Verifies the app-lock safety rules: opt-in (off by default) and fail-open
/// (always escapable). No real biometrics are exercised.
///
/// > Written, not built here: no Flutter SDK in this checkout. Runs in CI via
/// > `.github/workflows/client-mobile-build.yml` (`flutter test`).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const storageChannel =
      MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
  final store = <String, String>{};

  void mockStorage() {
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
        default:
          return null;
      }
    });
  }

  setUp(() {
    store.clear();
    mockStorage();
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(storageChannel, null);
  });

  group('AppLockState.canBypass (fail-open)', () {
    test('offers escape when auth is unavailable', () {
      const s = AppLockState(enabled: true, locked: true, available: false);
      expect(s.canBypass, isTrue);
    });

    test('offers escape after a failed unlock, even when available', () {
      const s = AppLockState(
          enabled: true, locked: true, available: true, unlockFailed: true);
      expect(s.canBypass, isTrue);
    });

    test('no escape on a healthy locked state before any failure', () {
      const s = AppLockState(enabled: true, locked: true, available: true);
      expect(s.canBypass, isFalse);
    });
  });

  test('lock is OFF by default (opt-in) — never locks until enabled', () async {
    // storage read returns null → not enabled.
    final c = AppLockController();
    // Let the async _init settle.
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(c.debugState.enabled, isFalse);
    expect(c.debugState.locked, isFalse);
    c.dispose();
  });

  test('setEnabled(false) persists and clears the lock', () async {
    final c = AppLockController();
    await Future<void>.delayed(const Duration(milliseconds: 20));
    await c.setEnabled(false);
    expect(c.debugState.enabled, isFalse);
    expect(c.debugState.locked, isFalse);
    expect(store['openidx.applock_enabled'], 'false');
    c.dispose();
  });

  test('bypass() unlocks (the escape hatch)', () async {
    final c = AppLockController();
    await Future<void>.delayed(const Duration(milliseconds: 20));
    c.bypass();
    expect(c.debugState.locked, isFalse);
    c.dispose();
  });
}
