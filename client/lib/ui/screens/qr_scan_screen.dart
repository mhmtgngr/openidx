import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../mobile/deep_links.dart';
import 'mobile/qr_login_approve_screen.dart';

/// Full-screen camera QR scanner. Handles two OpenIDX QR types:
///  - `openidx://enroll?code=…&server=…` → pops with the [EnrollLink] so the
///    caller (the enroll screen) can enrol.
///  - `openidx://qr-login?session=…` → replaces itself with the QR sign-in
///    approval screen.
///
/// Reading a QR off a glossy, back-lit screen is finicky, so the scanner is
/// tuned for it (QR-only detection, framing window, torch toggle) and *always*
/// offers a manual "enter the code" escape — the user is never trapped in a
/// camera that won't focus or that lacks permission.
class QrScanScreen extends StatefulWidget {
  const QrScanScreen({super.key});

  @override
  State<QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<QrScanScreen> {
  // Look for QR codes only — MLKit locks on much faster than when scanning
  // every barcode format.
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
      final link = OpenidxDeepLink.parse(Uri.tryParse(raw) ?? Uri());
      if (link is EnrollLink) {
        _handled = true;
        Navigator.of(context).pop(link);
        return;
      }
      if (link is LoginQrLink) {
        _handled = true;
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

  /// Escape hatch: return to the caller so the user can paste the code / tap the
  /// "Open in app" link instead of scanning.
  void _manualEntry() => Navigator.of(context).pop();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan QR code'),
        actions: [
          IconButton(
            tooltip: 'Toggle flash',
            icon: const Icon(Icons.flash_on),
            onPressed: () => _controller.toggleTorch(),
          ),
          IconButton(
            tooltip: 'Switch camera',
            icon: const Icon(Icons.cameraswitch),
            onPressed: () => _controller.switchCamera(),
          ),
        ],
      ),
      body: Stack(
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
            fit: BoxFit.cover,
            // Instead of a black screen, show why + how to continue when the
            // camera is denied/unavailable (also covers emulators with no camera).
            errorBuilder: (context, error, child) => _CameraError(
              onManual: _manualEntry,
            ),
          ),
          // Framing window so the user aims at the QR (closer framing = better
          // focus + recognition).
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
          Align(
            alignment: Alignment.bottomCenter,
            child: Container(
              width: double.infinity,
              color: Colors.black54,
              padding: const EdgeInsets.all(16),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text(
                    'Aim at the QR in your OpenIDX console. Hold ~15–20 cm away; '
                    'turn the flash OFF for a bright screen.',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: Colors.white),
                  ),
                  const SizedBox(height: 8),
                  TextButton.icon(
                    onPressed: _manualEntry,
                    icon: const Icon(Icons.keyboard, color: Colors.white),
                    label: const Text('Enter code manually',
                        style: TextStyle(color: Colors.white)),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// Shown when the camera can't start (permission denied, no camera hardware,
/// e.g. an emulator). Offers the manual path instead of a dead black screen.
class _CameraError extends StatelessWidget {
  const _CameraError({required this.onManual});
  final VoidCallback onManual;

  @override
  Widget build(BuildContext context) {
    return ColoredBox(
      color: Theme.of(context).colorScheme.surface,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.no_photography_outlined, size: 48),
              const SizedBox(height: 12),
              const Text(
                'Camera unavailable',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 8),
              const Text(
                'Grant camera permission, or enter the enrollment code manually.',
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: onManual,
                icon: const Icon(Icons.keyboard),
                label: const Text('Enter code manually'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
