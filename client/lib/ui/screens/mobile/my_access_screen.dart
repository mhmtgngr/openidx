import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../api/access.dart';
import '../../../api/governance.dart';
import '../../../state/mobile_providers.dart';
import '../../../state/providers.dart';

/// The signed-in user's own access: the zero-trust apps they can reach over the
/// network (tap to connect through the engine) and their access requests.
class MyAccessScreen extends ConsumerWidget {
  const MyAccessScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final requests = ref.watch(myRequestsProvider);
    final ziti = ref.watch(myZitiServicesProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('My Access')),
      body: RefreshIndicator(
        onRefresh: () async {
          ref.invalidate(myRequestsProvider);
          ref.invalidate(myZitiServicesProvider);
        },
        child: ListView(
          padding: const EdgeInsets.all(12),
          children: [
            // Zero-trust apps section (only when the user has some).
            ziti.maybeWhen(
              data: (services) => services.isEmpty
                  ? const SizedBox.shrink()
                  : _ZitiSection(services: services),
              orElse: () => const SizedBox.shrink(),
            ),

            // Access requests section.
            const Padding(
              padding: EdgeInsets.only(top: 8, bottom: 8, left: 4),
              child: Text('Access requests',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
            ),
            requests.when(
              loading: () => const Padding(
                padding: EdgeInsets.all(24),
                child: Center(child: CircularProgressIndicator()),
              ),
              error: (e, _) => Padding(
                padding: const EdgeInsets.all(24),
                child: Center(child: Text('Could not load requests: $e')),
              ),
              data: (items) {
                if (items.isEmpty) {
                  return const Padding(
                    padding: EdgeInsets.all(24),
                    child: Center(child: Text('You have no access requests')),
                  );
                }
                return Column(
                  children: [
                    for (final r in items)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 8),
                        child: _RequestTile(request: r),
                      ),
                  ],
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _ZitiSection extends ConsumerWidget {
  const _ZitiSection({required this.services});
  final List<ZitiService> services;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.only(bottom: 8, left: 4),
          child: Row(
            children: [
              Icon(Icons.verified_user, size: 18, color: Colors.green),
              SizedBox(width: 6),
              Text('Apps available over the network',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
            ],
          ),
        ),
        for (final s in services)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: _ZitiTile(service: s),
          ),
        const Divider(height: 24),
      ],
    );
  }
}

class _ZitiTile extends ConsumerWidget {
  const _ZitiTile({required this.service});
  final ZitiService service;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Card(
      child: ListTile(
        leading: const CircleAvatar(
          backgroundColor: Color(0xFFDCFCE7),
          child: Icon(Icons.lan, color: Color(0xFF15803D)),
        ),
        title: Text(service.name,
            style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (service.description.isNotEmpty) Text(service.description),
            if (service.endpoint.isNotEmpty)
              Text(service.endpoint,
                  style: const TextStyle(fontSize: 12, color: Colors.black54)),
          ],
        ),
        trailing: TextButton(
          onPressed: () => _connect(context, ref),
          child: const Text('Connect'),
        ),
      ),
    );
  }

  Future<void> _connect(BuildContext context, WidgetRef ref) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      final where = await ref.read(engineClientProvider).zitiDial(service.name);
      if (!context.mounted) return;
      messenger.showSnackBar(SnackBar(
        content: Text(where.isEmpty
            ? 'Connected to ${service.name}'
            : 'Connect ${service.name} at $where'),
      ));
    } catch (e) {
      if (!context.mounted) return;
      messenger.showSnackBar(
          SnackBar(content: Text('Could not connect to ${service.name}: $e')));
    }
  }
}

class _RequestTile extends StatelessWidget {
  const _RequestTile({required this.request});
  final AccessRequest request;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        title: Text(request.title,
            style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (request.resource.isNotEmpty) Text(request.resource),
            if (request.requestedAt.isNotEmpty)
              Text('Requested ${request.requestedAt}',
                  style: const TextStyle(fontSize: 12)),
          ],
        ),
        trailing: _StatusBadge(status: request.status),
      ),
    );
  }
}

class _StatusBadge extends StatelessWidget {
  const _StatusBadge({required this.status});
  final String status;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final (color, icon) = switch (status.toLowerCase()) {
      'approved' || 'granted' => (Colors.green, Icons.check_circle),
      'denied' || 'rejected' => (scheme.error, Icons.cancel),
      'expired' => (Colors.grey, Icons.timer_off),
      _ => (Colors.orange, Icons.hourglass_bottom),
    };
    return Chip(
      avatar: Icon(icon, size: 16, color: color),
      label: Text(status, style: TextStyle(fontSize: 12, color: color)),
      visualDensity: VisualDensity.compact,
    );
  }
}
