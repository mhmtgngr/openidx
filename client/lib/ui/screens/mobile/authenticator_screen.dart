import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../../features/totp.dart';
import '../../../state/api_providers.dart';

/// Offline TOTP authenticator: the user's saved accounts with live 6-digit
/// codes and a per-period countdown ring. Secrets never leave the device;
/// codes are generated in Dart (`features/totp.dart`). Adding an account either
/// scans the `otpauth://` QR shown on the computer (see [_OtpQrScanScreen]) or
/// accepts the URI pasted manually (see [_AddSheet]).
class AuthenticatorScreen extends ConsumerStatefulWidget {
  const AuthenticatorScreen({super.key});

  @override
  ConsumerState<AuthenticatorScreen> createState() =>
      _AuthenticatorScreenState();
}

class _AuthenticatorScreenState extends ConsumerState<AuthenticatorScreen> {
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    // Rebuild every second to advance codes + countdown.
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _ticker?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final accounts = ref.watch(authenticatorProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('Codes')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _openAdd,
        icon: const Icon(Icons.add),
        label: const Text('Add'),
      ),
      body: accounts.isEmpty
          ? const _EmptyCodes()
          : ListView.separated(
              padding: const EdgeInsets.all(12),
              itemCount: accounts.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (context, i) => _CodeTile(account: accounts[i]),
            ),
    );
  }

  Future<void> _openAdd() async {
    final uri = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      builder: (_) => const _AddSheet(),
    );
    if (uri == null || uri.isEmpty) return;
    try {
      await ref.read(authenticatorProvider.notifier).addFromUri(uri);
    } on FormatException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Invalid otpauth URI: ${e.message}')),
        );
      }
    }
  }
}

class _CodeTile extends ConsumerWidget {
  const _CodeTile({required this.account});
  final OtpAccount account;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final code = account.code();
    final remaining = Totp.secondsRemaining(periodSeconds: account.period);
    final progress = remaining / account.period;
    final display = code.length > 3
        ? '${code.substring(0, code.length ~/ 2)} ${code.substring(code.length ~/ 2)}'
        : code;

    return Card(
      child: ListTile(
        title: Text(
          account.issuer.isNotEmpty ? account.issuer : account.account,
          style: const TextStyle(fontWeight: FontWeight.w600),
        ),
        subtitle: Text(account.account),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              display,
              style: const TextStyle(
                fontSize: 22,
                fontFeatures: [FontFeature.tabularFigures()],
                letterSpacing: 1.5,
              ),
            ),
            const SizedBox(width: 12),
            SizedBox(
              width: 28,
              height: 28,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  CircularProgressIndicator(value: progress, strokeWidth: 3),
                  Text('$remaining', style: const TextStyle(fontSize: 11)),
                ],
              ),
            ),
          ],
        ),
        onTap: () {
          Clipboard.setData(ClipboardData(text: code));
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Code copied')),
          );
        },
        onLongPress: () => _confirmRemove(context, ref),
      ),
    );
  }

  Future<void> _confirmRemove(BuildContext context, WidgetRef ref) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Remove account?'),
        content: Text('${account.issuer} (${account.account})'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Remove')),
        ],
      ),
    );
    if (ok == true) {
      await ref.read(authenticatorProvider.notifier).remove(account.id);
    }
  }
}

class _AddSheet extends StatefulWidget {
  const _AddSheet();

  @override
  State<_AddSheet> createState() => _AddSheetState();
}

class _AddSheetState extends State<_AddSheet> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _scan() async {
    final uri = await Navigator.of(context).push<String>(
      MaterialPageRoute<String>(builder: (_) => const _OtpQrScanScreen()),
    );
    if (uri == null || uri.isEmpty) return;
    // Scanning gives us the whole otpauth:// URI — add it straight away.
    if (mounted) Navigator.pop(context, uri);
  }

  @override
  Widget build(BuildContext context) {
    final insets = MediaQuery.of(context).viewInsets;
    return Padding(
      padding: EdgeInsets.fromLTRB(16, 16, 16, 16 + insets.bottom),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text('Add account',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          const Text(
            'Scan the QR code shown on your computer, or paste the setup key.',
            style: TextStyle(fontSize: 13, color: Colors.black54),
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            onPressed: _scan,
            icon: const Icon(Icons.qr_code_scanner),
            label: const Text('Scan QR code'),
          ),
          const SizedBox(height: 16),
          const Row(children: [
            Expanded(child: Divider()),
            Padding(
              padding: EdgeInsets.symmetric(horizontal: 8),
              child: Text('or paste', style: TextStyle(fontSize: 12)),
            ),
            Expanded(child: Divider()),
          ]),
          const SizedBox(height: 8),
          TextField(
            controller: _controller,
            decoration: const InputDecoration(
              labelText: 'otpauth:// URI',
              hintText: 'otpauth://totp/Issuer:you@example.com?secret=…',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          OutlinedButton(
            onPressed: () => Navigator.pop(context, _controller.text.trim()),
            child: const Text('Add from pasted URI'),
          ),
        ],
      ),
    );
  }
}

/// Full-screen camera that returns the first `otpauth://` QR it sees. Kept
/// separate from the enroll/login scanner (qr_scan_screen.dart) because it
/// yields a raw otpauth URI rather than an OpenIDX deep link.
class _OtpQrScanScreen extends StatefulWidget {
  const _OtpQrScanScreen();

  @override
  State<_OtpQrScanScreen> createState() => _OtpQrScanScreenState();
}

class _OtpQrScanScreenState extends State<_OtpQrScanScreen> {
  final _controller = MobileScannerController(
    formats: const [BarcodeFormat.qrCode],
    detectionSpeed: DetectionSpeed.noDuplicates,
  );
  bool _handled = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw == null || raw.isEmpty) continue;
      final uri = Uri.tryParse(raw);
      if (uri != null &&
          uri.scheme == 'otpauth' &&
          uri.host.toLowerCase() == 'totp') {
        _handled = true;
        Navigator.of(context).pop(raw);
        return;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan authenticator QR'),
        actions: [
          IconButton(
            tooltip: 'Toggle flash',
            icon: const Icon(Icons.flash_on),
            onPressed: () => _controller.toggleTorch(),
          ),
        ],
      ),
      body: Stack(
        children: [
          MobileScanner(controller: _controller, onDetect: _onDetect),
          IgnorePointer(
            child: Center(
              child: Container(
                width: 240,
                height: 240,
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.white, width: 3),
                  borderRadius: BorderRadius.circular(16),
                ),
              ),
            ),
          ),
          const Positioned(
            left: 0,
            right: 0,
            bottom: 48,
            child: Center(
              child: Text(
                'Point at the MFA QR on your computer screen',
                style: TextStyle(color: Colors.white, fontSize: 14),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _EmptyCodes extends StatelessWidget {
  const _EmptyCodes();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.qr_code_2, size: 48),
          SizedBox(height: 12),
          Text('No authenticator accounts yet'),
          SizedBox(height: 4),
          Text('Tap Add to paste an otpauth:// URI',
              style: TextStyle(fontSize: 12)),
        ],
      ),
    );
  }
}
