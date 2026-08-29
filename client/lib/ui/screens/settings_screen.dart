import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../mobile/app_lock.dart';
import '../../state/providers.dart';
import 'enroll_screen.dart';
import 'mobile/control_logs_screen.dart';

/// Settings: shows the connected server, signs out, or quits the app.
class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  Future<void> _signOut(BuildContext context, WidgetRef ref) async {
    try {
      await ref.read(engineActionsProvider).logout();
      if (context.mounted) Navigator.of(context).pop();
    } on Object catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Sign out failed: $e')));
      }
    }
  }

  Future<void> _quit(BuildContext context, WidgetRef ref) async {
    // Let the supervisor tear down a spawned engine before we exit. On mobile
    // there is no supervisor (the engine is in-process) and no "quit", so this
    // is desktop-only — see the tile's visibility guard below.
    await ref.read(engineSupervisorProvider)?.dispose();
    exit(0);
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final status = ref.watch(currentStatusProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          ListTile(
            leading: const Icon(Icons.cloud_outlined),
            title: const Text('Server'),
            subtitle: Text(status.serverUrl.isEmpty ? '—' : status.serverUrl),
          ),
          ListTile(
            leading: const Icon(Icons.badge_outlined),
            title: const Text('Signed in as'),
            subtitle: Text(
              status.userEmail.isNotEmpty ? status.userEmail : status.userSub,
            ),
          ),
          ListTile(
            leading: const Icon(Icons.devices_other_outlined),
            title: const Text('Device ID'),
            subtitle: Text(status.deviceId.isEmpty ? '—' : status.deviceId),
          ),
          // Network access (OpenZiti) is a separate step from the authenticator:
          // it needs device enrollment with a code. Signed-in-but-not-enrolled
          // users reach it here (scan QR / tap link / paste code). Once enrolled,
          // show the overlay status instead.
          if (Platform.isIOS || Platform.isAndroid)
            status.enrolled
                ? ListTile(
                    leading: const Icon(Icons.hub_outlined),
                    title: const Text('Network access'),
                    subtitle: Text(status.zitiEnrolled
                        ? 'OpenZiti overlay connected'
                        : 'Device enrolled'),
                    trailing: Icon(
                      status.zitiEnrolled ? Icons.check_circle : Icons.check,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  )
                : ListTile(
                    leading: const Icon(Icons.hub_outlined),
                    title: const Text('Set up network access'),
                    subtitle: const Text(
                        'Enroll this device for OpenZiti access (needs a code)'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute<void>(
                        builder: (_) => const EnrollScreen(),
                      ),
                    ),
                  ),
          const Divider(),
          // Biometric app-lock — opt-in (off by default) so an authenticator
          // app never traps the user out on a device where biometrics fail.
          if (Platform.isIOS || Platform.isAndroid)
            SwitchListTile(
              secondary: const Icon(Icons.fingerprint),
              title: const Text('Require biometric unlock'),
              subtitle: const Text(
                  'Lock the app with Face ID / fingerprint / device PIN'),
              value: ref.watch(appLockProvider).enabled,
              onChanged: (v) => ref.read(appLockProvider.notifier).setEnabled(v),
            ),
          // Control logs viewer — mobile only (the engine runs in-process via
          // the gomobile plugin, which exposes its log tail over the channel).
          if (Platform.isIOS || Platform.isAndroid)
            ListTile(
              leading: const Icon(Icons.article_outlined),
              title: const Text('Control logs'),
              subtitle: const Text('Engine / control-plane activity'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                  builder: (_) => const ControlLogsScreen(),
                ),
              ),
            ),
          ListTile(
            leading: const Icon(Icons.logout),
            title: const Text('Sign out'),
            onTap: () => _signOut(context, ref),
          ),
          // "Quit" is a desktop-only concept (mobile apps are backgrounded,
          // not quit, and there is no spawned engine to tear down).
          if (!Platform.isIOS && !Platform.isAndroid)
            ListTile(
              leading: const Icon(Icons.power_settings_new),
              title: const Text('Quit OpenIDX'),
              onTap: () => _quit(context, ref),
            ),
        ],
      ),
    );
  }
}
