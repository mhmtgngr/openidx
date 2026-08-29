import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../state/providers.dart';
import 'enroll_screen.dart';

/// First screen on a fresh (not-signed-in, not-enrolled) install.
///
/// The **primary** path is "sign in" — like Okta Verify / Microsoft
/// Authenticator, you sign in with your account and this phone becomes your
/// authenticator automatically (push registration happens right after login,
/// see MobileOAuthLoginHandler). **No enrollment code needed.**
///
/// The secondary path is the full device enrollment (network access / posture /
/// PAM), which does need a code — reached via "Have an enrollment code?".
class WelcomeScreen extends ConsumerStatefulWidget {
  const WelcomeScreen({super.key});

  @override
  ConsumerState<WelcomeScreen> createState() => _WelcomeScreenState();
}

class _WelcomeScreenState extends ConsumerState<WelcomeScreen> {
  final _serverController =
      TextEditingController(text: 'https://openidx.tdv.org');
  bool _busy = false;
  String? _error;
  bool _showEnroll = false;

  @override
  void dispose() {
    _serverController.dispose();
    super.dispose();
  }

  Future<void> _signIn() async {
    final server = _serverController.text.trim();
    if (server.isEmpty) {
      setState(() => _error = 'Enter the server URL.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final actions = ref.read(engineActionsProvider);
      // Mobile has no seeded server; point the engine at it before login.
      await actions.setServer(server);
      if (Platform.isAndroid || Platform.isIOS) {
        // Open the OAuth authorize URL in the system browser. Completion is owned
        // by the app-level MobileOAuthLoginHandler (survives a cold start), which
        // also auto-registers this phone as a push approver on success. The
        // router advances to the app once login lands.
        final url = await actions.loginStart();
        await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
      } else {
        await actions.login();
      }
    } on Object catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_showEnroll) return const EnrollScreen();

    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 460),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(Icons.shield_outlined, size: 56),
                const SizedBox(height: 16),
                Text('OpenIDX',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 8),
                Text(
                  'Sign in to use this phone as your authenticator. '
                  'No code needed — approving your logins is set up automatically.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 24),
                TextField(
                  controller: _serverController,
                  enabled: !_busy,
                  keyboardType: TextInputType.url,
                  autocorrect: false,
                  decoration: const InputDecoration(
                    labelText: 'Server URL',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.dns_outlined),
                  ),
                ),
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: _busy ? null : _signIn,
                  icon: _busy
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.login),
                  label: const Text('Sign in'),
                ),
                if (_error != null) ...[
                  const SizedBox(height: 16),
                  Text(
                    _error!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                      fontSize: 13,
                    ),
                    textAlign: TextAlign.center,
                  ),
                ],
                const SizedBox(height: 24),
                const Divider(),
                const SizedBox(height: 8),
                TextButton.icon(
                  onPressed: _busy ? null : () => setState(() => _showEnroll = true),
                  icon: const Icon(Icons.vpn_key_outlined),
                  label: const Text('Have an enrollment code? Set up device access'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
