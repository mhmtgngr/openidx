import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../mobile/deep_links.dart';
import '../../state/providers.dart';

/// Shown when the device is not yet enrolled. The user pastes an enrollment
/// code, which the engine exchanges via `/enroll`.
class EnrollScreen extends ConsumerStatefulWidget {
  const EnrollScreen({super.key});

  @override
  ConsumerState<EnrollScreen> createState() => _EnrollScreenState();
}

class _EnrollScreenState extends ConsumerState<EnrollScreen> {
  final _controller = TextEditingController();
  // The engine has no seeded server on a fresh install, so the user provides it.
  // Defaulted to the public server; editable for other deployments.
  final _serverController =
      TextEditingController(text: 'https://openidx.tdv.org');
  bool _busy = false;
  String? _error;
  StreamSubscription<OpenidxDeepLink>? _linkSub;

  @override
  void initState() {
    super.initState();
    // QR-free enrollment: if the app was opened by an openidx://enroll link
    // (cold start) or one arrives while this screen is up, prefill + enroll.
    Future.microtask(() async {
      final svc = ref.read(deepLinkServiceProvider);
      final initial = await svc.initialEnrollLink();
      if (initial != null) {
        svc.clearEnrollLink();
        _applyEnrollLink(initial);
      }
      _linkSub = svc.links
          .where((l) => l is EnrollLink)
          .cast<EnrollLink>()
          .listen(_applyEnrollLink);
    });
  }

  void _applyEnrollLink(EnrollLink link) {
    if (_busy) return;
    _controller.text = link.code;
    if (link.server.isNotEmpty) _serverController.text = link.server;
    _enroll();
  }

  @override
  void dispose() {
    _linkSub?.cancel();
    _controller.dispose();
    _serverController.dispose();
    super.dispose();
  }

  Future<void> _enroll() async {
    final code = _controller.text.trim();
    final server = _serverController.text.trim();
    if (code.isEmpty) {
      setState(() => _error = 'Enter an enrollment code.');
      return;
    }
    if (server.isEmpty) {
      setState(() => _error = 'Enter the server URL.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(engineActionsProvider).enroll(code, serverUrl: server);
      // Status refresh drives the router to the login screen.
    } on Object catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      // Scrollable so the on-screen keyboard doesn't overflow the layout.
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 460),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(Icons.qr_code_2, size: 56),
                const SizedBox(height: 16),
                Text(
                  'Enroll this device',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 8),
                Text(
                  'Tap the enrollment link on this phone, or paste the code '
                  'from your OpenIDX console below — no QR scan needed.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 24),
                TextField(
                  controller: _controller,
                  autofocus: true,
                  enabled: !_busy,
                  decoration: const InputDecoration(
                    labelText: 'Enrollment code',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.vpn_key_outlined),
                  ),
                  onSubmitted: (_) => _enroll(),
                ),
                const SizedBox(height: 12),
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
                  onSubmitted: (_) => _enroll(),
                ),
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: _busy ? null : _enroll,
                  icon: _busy
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.check),
                  label: const Text('Enroll'),
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
              ],
            ),
          ),
        ),
      ),
    );
  }
}
