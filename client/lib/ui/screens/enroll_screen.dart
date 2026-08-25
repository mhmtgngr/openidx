import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../mobile/deep_links.dart';
import '../../state/providers.dart';
import 'mobile/control_logs_screen.dart';

/// Shown when the device is not yet enrolled. The user pastes an enrollment
/// code, which the engine exchanges via `/enroll`.
///
/// On mobile the screen also collects the **server URL**, because the engine
/// starts with no configured server and (unlike desktop, which has
/// `openidx-agent enroll --server …`) has no other way to learn one. Opening the
/// admin console's `openidx://enroll?code=…&server=…` link fills both fields and
/// submits automatically; typing the code by hand still works as long as the
/// server is filled in.
class EnrollScreen extends ConsumerStatefulWidget {
  const EnrollScreen({super.key});

  @override
  ConsumerState<EnrollScreen> createState() => _EnrollScreenState();
}

class _EnrollScreenState extends ConsumerState<EnrollScreen> {
  final _codeController = TextEditingController();
  final _serverController = TextEditingController();
  StreamSubscription<OpenidxDeepLink>? _linkSub;
  bool _busy = false;
  String? _error;

  /// Mobile is the only platform that needs the server field: desktop's config
  /// already carries one by the time the GUI runs.
  bool get _isMobile => Platform.isIOS || Platform.isAndroid;

  @override
  void initState() {
    super.initState();
    // Prefill from a previously configured server (e.g. a re-enrollment after
    // logout), so the common case is code-only.
    final known = ref.read(currentStatusProvider).serverUrl;
    if (known.isNotEmpty) _serverController.text = known;
    if (_isMobile) unawaited(_listenForEnrollLinks());
  }

  /// Subscribe to `openidx://enroll` links (cold-start included) and enroll with
  /// what they carry.
  Future<void> _listenForEnrollLinks() async {
    final service = ref.read(deepLinkServiceProvider);
    _linkSub = service.links.listen((link) {
      if (link is! EnrollLink || !mounted) return;
      setState(() {
        _codeController.text = link.code;
        if (link.server.isNotEmpty) _serverController.text = link.server;
        _error = null;
      });
      unawaited(_enroll());
    });
    await service.init();
  }

  @override
  void dispose() {
    unawaited(_linkSub?.cancel());
    _codeController.dispose();
    _serverController.dispose();
    super.dispose();
  }

  Future<void> _enroll() async {
    final code = _codeController.text.trim();
    final server = _serverController.text.trim();
    if (code.isEmpty) {
      setState(() => _error = 'Enter an enrollment code.');
      return;
    }
    if (_isMobile && server.isEmpty) {
      setState(() => _error = 'Enter the OpenIDX server URL.');
      return;
    }
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final actions = ref.read(engineActionsProvider);
      // Must precede enroll: without a server the engine rejects the code
      // before any request leaves the device.
      if (_isMobile) await actions.setServer(server);
      await actions.enroll(code);
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
      body: Center(
        child: SingleChildScrollView(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 460),
            child: Padding(
              padding: const EdgeInsets.all(32),
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
                    _isMobile
                        ? 'Open the enrollment link from your OpenIDX admin '
                            'console, or enter the server and code below.'
                        : 'Enter the enrollment code from your OpenIDX admin '
                            'console.',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  const SizedBox(height: 24),
                  if (_isMobile) ...[
                    TextField(
                      controller: _serverController,
                      enabled: !_busy,
                      keyboardType: TextInputType.url,
                      autocorrect: false,
                      decoration: const InputDecoration(
                        labelText: 'Server URL',
                        hintText: 'https://openidx.example.com',
                        border: OutlineInputBorder(),
                        prefixIcon: Icon(Icons.dns_outlined),
                      ),
                    ),
                    const SizedBox(height: 16),
                  ],
                  TextField(
                    controller: _codeController,
                    autofocus: true,
                    enabled: !_busy,
                    autocorrect: false,
                    decoration: const InputDecoration(
                      labelText: 'Enrollment code',
                      border: OutlineInputBorder(),
                      prefixIcon: Icon(Icons.vpn_key_outlined),
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
                  // Reachable *before* enrollment on purpose: enrollment
                  // failures are exactly what the log explains, and Settings
                  // (the other entry point) only exists once signed in.
                  if (_isMobile) ...[
                    const SizedBox(height: 8),
                    TextButton.icon(
                      onPressed: _busy
                          ? null
                          : () => Navigator.of(context).push(
                                MaterialPageRoute<void>(
                                  builder: (_) => const ControlLogsScreen(),
                                ),
                              ),
                      icon: const Icon(Icons.article_outlined, size: 18),
                      label: const Text('View control logs'),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
