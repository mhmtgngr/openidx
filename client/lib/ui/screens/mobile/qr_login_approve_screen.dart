import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../api/qr_login.dart';
import '../../../state/mobile_providers.dart';

/// Approve (or deny) a desktop "sign in with QR" request. Reached after the
/// camera scanner reads an `openidx://qr-login?session=…` QR.
///
/// On mount it binds the session to this phone's user (scan) and shows the
/// desktop request context; the user then approves — logging the desktop in —
/// or denies.
class QrLoginApproveScreen extends ConsumerStatefulWidget {
  const QrLoginApproveScreen({required this.sessionToken, super.key});

  final String sessionToken;

  @override
  ConsumerState<QrLoginApproveScreen> createState() =>
      _QrLoginApproveScreenState();
}

class _QrLoginApproveScreenState extends ConsumerState<QrLoginApproveScreen> {
  QrLoginContext? _ctx;
  bool _busy = true;
  bool _done = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _scan();
  }

  Future<void> _scan() async {
    try {
      final ctx = await ref.read(qrLoginApiProvider).scan(
            widget.sessionToken,
            deviceName: 'OpenIDX mobile',
            os: Platform.operatingSystem,
          );
      if (mounted) setState(() => _ctx = ctx);
    } on Object catch (e) {
      if (mounted) setState(() => _error = _friendly(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _decide(bool approve) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final api = ref.read(qrLoginApiProvider);
      if (approve) {
        await api.approve(widget.sessionToken);
      } else {
        await api.reject(widget.sessionToken);
      }
      if (mounted) setState(() => _done = true);
      await Future<void>.delayed(const Duration(milliseconds: 900));
      if (mounted) Navigator.of(context).pop();
    } on Object catch (e) {
      if (mounted) {
        setState(() {
          _error = _friendly(e);
          _busy = false;
        });
      }
    }
  }

  String _friendly(Object e) {
    final s = e.toString();
    if (s.contains('expired')) return 'This sign-in request has expired. Refresh the QR and try again.';
    if (s.contains('qr_login') || s.contains('disabled')) {
      return 'QR sign-in is disabled for your account.';
    }
    return 'Could not complete the sign-in request.';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Sign-in request')),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: _done
              ? const Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.check_circle, size: 56, color: Colors.green),
                    SizedBox(height: 12),
                    Text('Done — check your computer.',
                        style: TextStyle(fontSize: 16)),
                  ],
                )
              : Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Icon(Icons.desktop_windows_outlined, size: 56),
                    const SizedBox(height: 16),
                    Text('Sign in on your computer?',
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.headlineSmall),
                    const SizedBox(height: 8),
                    Text(
                      'Only approve if you started this sign-in.',
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                    const SizedBox(height: 20),
                    if (_ctx != null) _contextCard(_ctx!),
                    if (_error != null) ...[
                      const SizedBox(height: 16),
                      Text(_error!,
                          textAlign: TextAlign.center,
                          style: TextStyle(
                              color: Theme.of(context).colorScheme.error)),
                    ],
                    const SizedBox(height: 24),
                    if (_busy)
                      const Center(child: CircularProgressIndicator())
                    else if (_error == null) ...[
                      FilledButton.icon(
                        onPressed: () => _decide(true),
                        icon: const Icon(Icons.check),
                        label: const Text('Approve'),
                      ),
                      const SizedBox(height: 8),
                      OutlinedButton.icon(
                        onPressed: () => _decide(false),
                        icon: const Icon(Icons.close),
                        label: const Text('Deny'),
                      ),
                    ],
                  ],
                ),
        ),
      ),
    );
  }

  Widget _contextCard(QrLoginContext c) {
    final rows = <Widget>[
      if (c.device.isNotEmpty) _row(Icons.devices, c.device),
      if (c.location.isNotEmpty) _row(Icons.location_on_outlined, c.location),
      if (c.ipAddress.isNotEmpty) _row(Icons.public, c.ipAddress),
    ];
    if (rows.isEmpty) return const SizedBox.shrink();
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(mainAxisSize: MainAxisSize.min, children: rows),
      ),
    );
  }

  Widget _row(IconData icon, String text) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(children: [
          Icon(icon, size: 18),
          const SizedBox(width: 10),
          Expanded(child: Text(text)),
        ]),
      );
}
