import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

/// Biometric app-lock state.
///
/// This is an authenticator app, so being locked out of it is worse than the
/// marginal protection a lock provides. Two safety rules follow:
///   1. **Opt-in** — the lock is OFF by default; the user enables it in Settings.
///   2. **Fail-open** — if biometrics/device-credential aren't available or the
///      prompt keeps failing (common on old Android), the lock overlay always
///      offers a "Continue" escape so the user is never trapped out.
class AppLockState {
  const AppLockState({
    required this.enabled,
    required this.locked,
    required this.available,
    this.unlockFailed = false,
  });

  /// User preference: is the biometric lock turned on at all? Default false.
  final bool enabled;

  /// Whether the lock overlay is currently blocking the UI.
  final bool locked;

  /// Whether any local authentication (biometric or device credential) exists.
  final bool available;

  /// True once an unlock attempt has failed — surfaces the "Continue" escape so
  /// a device where auth doesn't work can still get in.
  final bool unlockFailed;

  /// The overlay offers the fail-open escape when auth isn't available at all,
  /// or after at least one failed unlock attempt.
  bool get canBypass => !available || unlockFailed;

  AppLockState copyWith({
    bool? enabled,
    bool? locked,
    bool? available,
    bool? unlockFailed,
  }) =>
      AppLockState(
        enabled: enabled ?? this.enabled,
        locked: locked ?? this.locked,
        available: available ?? this.available,
        unlockFailed: unlockFailed ?? this.unlockFailed,
      );
}

class AppLockController extends StateNotifier<AppLockState> {
  AppLockController({
    LocalAuthentication? auth,
    FlutterSecureStorage? storage,
    this.idleTimeout = const Duration(minutes: 2),
  })  : _auth = auth ?? LocalAuthentication(),
        _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
            ),
        // Start unlocked: the lock is opt-in, so nothing blocks until _init
        // confirms the user enabled it AND the device supports auth.
        super(const AppLockState(
            enabled: false, locked: false, available: false)) {
    _init();
  }

  final LocalAuthentication _auth;
  final FlutterSecureStorage _storage;
  final Duration idleTimeout;
  DateTime? _backgroundedAt;

  static const _kEnabled = 'openidx.applock_enabled';

  Future<void> _init() async {
    final enabled = (await _readEnabled());
    if (!enabled) {
      state = const AppLockState(enabled: false, locked: false, available: false);
      return;
    }
    final supported = await _isSupported();
    // Enabled + supported → lock and prompt. Enabled but the device can't
    // authenticate → fail-open (don't trap the user).
    state = AppLockState(enabled: true, available: supported, locked: supported);
    if (supported) {
      await unlock();
    }
  }

  Future<bool> _readEnabled() async {
    try {
      return (await _storage.read(key: _kEnabled)) == 'true';
    } on Object {
      return false;
    }
  }

  Future<bool> _isSupported() async {
    try {
      final canCheck = await _auth.canCheckBiometrics;
      final supported = await _auth.isDeviceSupported();
      return canCheck || supported;
    } on Object {
      // Old Android / plugin error → treat as unavailable (fail-open).
      return false;
    }
  }

  /// Turn the biometric lock on/off (persisted). Turning it on locks immediately
  /// (and prompts); turning it off clears the lock.
  Future<void> setEnabled(bool enabled) async {
    try {
      await _storage.write(key: _kEnabled, value: enabled ? 'true' : 'false');
    } on Object {
      // Non-fatal: apply in-memory even if persistence fails.
    }
    if (!enabled) {
      state = const AppLockState(enabled: false, locked: false, available: false);
      return;
    }
    final supported = await _isSupported();
    state = AppLockState(enabled: true, available: supported, locked: supported);
    if (supported) await unlock();
  }

  /// Prompt for biometrics/device credential. On success, unlock. On failure,
  /// set [AppLockState.unlockFailed] so the overlay reveals the escape.
  Future<bool> unlock() async {
    if (!state.available) {
      state = state.copyWith(locked: false);
      return true;
    }
    try {
      final ok = await _auth.authenticate(
        localizedReason: 'Unlock OpenIDX',
        options: const AuthenticationOptions(
          biometricOnly: false,
          stickyAuth: true,
        ),
      );
      if (ok) {
        state = state.copyWith(locked: false, unlockFailed: false);
      } else {
        state = state.copyWith(unlockFailed: true);
      }
      return ok;
    } on PlatformException {
      // NotAvailable / NotEnrolled / PasscodeNotSet / old-API errors: the device
      // can't actually authenticate → don't trap the user, reveal the escape.
      state = state.copyWith(available: false, locked: false, unlockFailed: true);
      return false;
    } on Object {
      state = state.copyWith(unlockFailed: true);
      return false;
    }
  }

  /// Fail-open escape: dismiss the lock without authenticating. Only reachable
  /// from the overlay when [AppLockState.canBypass] is true.
  void bypass() {
    state = state.copyWith(locked: false);
  }

  /// Call from `didChangeAppLifecycleState`. Records background time; on resume
  /// re-locks if idle longer than [idleTimeout].
  void onLifecycle(AppLifecycleState lifecycle) {
    if (!state.enabled || !state.available) return;
    if (lifecycle == AppLifecycleState.paused ||
        lifecycle == AppLifecycleState.inactive) {
      _backgroundedAt ??= DateTime.now();
    } else if (lifecycle == AppLifecycleState.resumed) {
      final since = _backgroundedAt;
      _backgroundedAt = null;
      if (since != null && DateTime.now().difference(since) >= idleTimeout) {
        state = state.copyWith(locked: true, unlockFailed: false);
      }
    }
  }
}

final appLockProvider =
    StateNotifierProvider<AppLockController, AppLockState>((ref) {
  return AppLockController();
});

/// Wraps [child] with a blocking lock overlay while the app is locked.
///
/// Also bridges app-lifecycle events into the controller so idle re-locking
/// works. Place it just under the mobile shell.
class AppLockGate extends ConsumerStatefulWidget {
  const AppLockGate({super.key, required this.child});
  final Widget child;

  @override
  ConsumerState<AppLockGate> createState() => _AppLockGateState();
}

class _AppLockGateState extends ConsumerState<AppLockGate>
    with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    ref.read(appLockProvider.notifier).onLifecycle(state);
  }

  @override
  Widget build(BuildContext context) {
    final lock = ref.watch(appLockProvider);
    return Stack(
      children: [
        widget.child,
        if (lock.locked)
          _LockOverlay(
            canBypass: lock.canBypass,
            onUnlock: () => ref.read(appLockProvider.notifier).unlock(),
            onBypass: () => ref.read(appLockProvider.notifier).bypass(),
          ),
      ],
    );
  }
}

class _LockOverlay extends StatelessWidget {
  const _LockOverlay({
    required this.onUnlock,
    required this.onBypass,
    required this.canBypass,
  });
  final VoidCallback onUnlock;
  final VoidCallback onBypass;
  final bool canBypass;

  @override
  Widget build(BuildContext context) {
    return Positioned.fill(
      child: Material(
        color: Theme.of(context).colorScheme.surface,
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.lock_outline, size: 56),
              const SizedBox(height: 16),
              const Text('OpenIDX is locked',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: onUnlock,
                icon: const Icon(Icons.fingerprint),
                label: const Text('Unlock'),
              ),
              if (canBypass) ...[
                const SizedBox(height: 8),
                TextButton(
                  onPressed: onBypass,
                  child: const Text("Can't unlock? Continue"),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
