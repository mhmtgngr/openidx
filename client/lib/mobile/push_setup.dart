import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../api/api_client.dart';
import '../state/api_providers.dart';
import '../state/providers.dart';

// Signing in is meant to make this phone the person's push approver. The
// sign-in handler registers it, but the server asks for the account password
// before adding a second factor to an account that already has one
// (internal/identity/factor_proof.go): a stolen token must not be able to add
// an authenticator of its own. The handler sent no password, so for anyone
// with TOTP or a key the registration was refused with 403 and the app said
// nothing; the phone never became an approver. The gate below asks for the
// password once, in the app, and registers the phone with it.

/// The outcome of one registration attempt.
enum PushSetupOutcome { registered, needsPassword, wrongPassword, locked, failed }

/// Maps a registration error to an outcome. The server answers every refusal
/// to prove ownership with 403 and a machine-readable code in `error`.
PushSetupOutcome pushSetupOutcomeOf(Object error) {
  if (error is ApiException && error.status == 403) {
    switch (error.message) {
      case 'reauthentication_required':
        return PushSetupOutcome.needsPassword;
      case 'reauthentication_failed':
        return PushSetupOutcome.wrongPassword;
      case 'reauthentication_locked':
        return PushSetupOutcome.locked;
    }
  }
  return PushSetupOutcome.failed;
}

/// Where the app remembers that this install's push token is registered. The
/// server never returns tokens, so the app cannot ask it; a reinstall mints a
/// new token and clears this with the rest of the keystore.
const pushRegisteredKey = 'openidx.push_registered';

/// Registers this phone as the signed-in person's push approver.
Future<PushSetupOutcome> registerThisPhone(WidgetRef ref, {String? password}) async {
  final push = await ref.read(pushTokenServiceProvider).resolve();
  if (push == null) return PushSetupOutcome.failed; // not a phone
  try {
    await ref.read(mfaApiProvider).registerPush(
          deviceToken: push.token,
          platform: push.platform,
          currentPassword: password,
        );
  } catch (e) {
    return pushSetupOutcomeOf(e);
  }
  await ref.read(secureStorageProvider).write(key: pushRegisteredKey, value: push.token);
  return PushSetupOutcome.registered;
}

/// Wraps the signed-in mobile shell. If this phone is not yet a push approver,
/// it registers it, asking for the account password when the server needs it.
class PushSetupGate extends ConsumerStatefulWidget {
  const PushSetupGate({super.key, required this.child});

  final Widget child;

  @override
  ConsumerState<PushSetupGate> createState() => _PushSetupGateState();
}

class _PushSetupGateState extends ConsumerState<PushSetupGate> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => unawaited(_ensure()));
  }

  Future<void> _ensure() async {
    final storage = ref.read(secureStorageProvider);
    final push = await ref.read(pushTokenServiceProvider).resolve();
    if (push == null) return;
    if (await storage.read(key: pushRegisteredKey) == push.token) return;
    final first = await registerThisPhone(ref);
    if (first != PushSetupOutcome.needsPassword || !mounted) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const _PasswordDialog(),
    );
  }

  @override
  Widget build(BuildContext context) => widget.child;
}

class _PasswordDialog extends ConsumerStatefulWidget {
  const _PasswordDialog();

  @override
  ConsumerState<_PasswordDialog> createState() => _PasswordDialogState();
}

class _PasswordDialogState extends ConsumerState<_PasswordDialog> {
  final _password = TextEditingController();
  bool _busy = false;
  String? _problem;

  @override
  void dispose() {
    _password.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() {
      _busy = true;
      _problem = null;
    });
    final outcome = await registerThisPhone(ref, password: _password.text);
    if (!mounted) return;
    switch (outcome) {
      case PushSetupOutcome.registered:
        Navigator.of(context).pop();
        ScaffoldMessenger.maybeOf(context)?.showSnackBar(
          const SnackBar(content: Text('This phone now approves your sign-ins.')),
        );
        return;
      case PushSetupOutcome.wrongPassword:
        _problem = 'That password is not right.';
      case PushSetupOutcome.locked:
        _problem = 'Too many attempts. Try again later.';
      case PushSetupOutcome.needsPassword:
        _problem = 'Enter your password.';
      case PushSetupOutcome.failed:
        _problem = 'The phone could not be registered. Try again.';
    }
    setState(() => _busy = false);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Approve sign-ins with this phone'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Your account already has a second factor. Enter your '
              'password to add this phone as another one.'),
          const SizedBox(height: 12),
          TextField(
            controller: _password,
            obscureText: true,
            autocorrect: false,
            enableSuggestions: false,
            autofocus: true,
            decoration: InputDecoration(labelText: 'Password', errorText: _problem),
            onSubmitted: (_) => _busy ? null : _submit(),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => Navigator.of(context).pop(),
          child: const Text('Not now'),
        ),
        FilledButton(
          onPressed: _busy ? null : _submit,
          child: const Text('Use this phone'),
        ),
      ],
    );
  }
}
