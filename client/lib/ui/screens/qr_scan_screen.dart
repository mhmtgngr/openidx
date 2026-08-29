import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../mobile/deep_links.dart';

/// Full-screen camera QR scanner for enrollment. Point the phone at the
/// console's QR (which encodes `openidx://enroll?code=…&server=…`). On a valid
/// enroll QR it pops with the parsed [EnrollLink]; the caller then enrolls.
///
/// Returns the [EnrollLink] via `Navigator.pop`, or null if cancelled.
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
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scan enrollment QR')),
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
