import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../mobile/deep_links.dart';
import 'mobile/qr_login_approve_screen.dart';

/// Full-screen camera QR scanner. Handles two OpenIDX QR types:
///  - `openidx://enroll?code=…&server=…` → pops with the [EnrollLink] so the
///    caller (the enroll screen) can enrol.
///  - `openidx://qr-login?session=…` → replaces itself with the QR sign-in
///    approval screen (scan a desktop login QR to sign it in).
class QrScanScreen extends StatefulWidget {
  const QrScanScreen({super.key});

  @override
  State<QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<QrScanScreen> {
  final _controller = MobileScannerController();
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
      final link = OpenidxDeepLink.parse(Uri.tryParse(raw) ?? Uri());
      if (link is EnrollLink) {
        _handled = true;
        Navigator.of(context).pop(link);
        return;
      }
      if (link is LoginQrLink) {
        _handled = true;
        // Swap the scanner for the approval screen (don't leave it in the stack).
        Navigator.of(context).pushReplacement(
          MaterialPageRoute<void>(
            builder: (_) =>
                QrLoginApproveScreen(sessionToken: link.sessionToken),
          ),
        );
        return;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scan QR code')),
      body: Stack(
        children: [
          MobileScanner(controller: _controller, onDetect: _onDetect),
          // Simple aiming guidance overlay.
          Align(
            alignment: Alignment.bottomCenter,
            child: Container(
              width: double.infinity,
              color: Colors.black54,
              padding: const EdgeInsets.all(16),
              child: const Text(
                'Point the camera at the QR code in your OpenIDX console.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.white),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
