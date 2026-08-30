import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../api/access.dart';
import '../../api/governance.dart';
import '../../api/portal.dart';
import '../../engine/models.dart';
import '../../state/api_providers.dart';
import '../../state/providers.dart';

/// Everything the signed-in user can reach, in one place — the client's
/// counterpart to the web console's "My Apps & Network".
///
/// The sections mirror that page and each hides itself when empty, so a user
/// with only network apps sees only that: sign-in apps, apps reachable over the
/// zero-trust network, other resources the server says they can reach, their
/// privileged (PAM) connections, and their access requests.
///
/// Connecting is delegated to whoever actually owns the path: the engine dials
/// Ziti services and brokers PAM sessions, and plain published apps open in the
/// browser. Nothing here decides access — every list comes from the server,
/// which applies the same predicates it enforces at connect time.
class MyAccessScreen extends ConsumerStatefulWidget {
  const MyAccessScreen({super.key, this.showAppBar = true});

  /// Desktop embeds this inside its own page, which already has a title.
  final bool showAppBar;

  @override
  ConsumerState<MyAccessScreen> createState() => _MyAccessScreenState();
}

class _MyAccessScreenState extends ConsumerState<MyAccessScreen> {
  String _query = '';

  bool _matches(String text) =>
      _query.isEmpty || text.toLowerCase().contains(_query);

  void _refresh() {
    ref.invalidate(myApplicationsProvider);
    ref.invalidate(myZitiServicesProvider);
    ref.invalidate(myResourcesProvider);
    ref.invalidate(pamEntriesProvider);
    ref.invalidate(myRequestsProvider);
  }

  @override
  Widget build(BuildContext context) {
    final apps = ref.watch(myApplicationsProvider);
    final ziti = ref.watch(myZitiServicesProvider);
    final resources = ref.watch(myResourcesProvider);
    final pam = ref.watch(pamEntriesProvider);
    final requests = ref.watch(myRequestsProvider);

    // A section that failed to load is left out rather than shown as an error
    // block: one unavailable backend must not hide the access the user does
    // have. The requests section, which is always rendered, reports its own
    // errors.
    final appList = (apps.valueOrNull ?? const <PortalApp>[])
        .where((a) => _matches('${a.name} ${a.description}'))
        .toList();
    final zitiList = (ziti.valueOrNull ?? const <ZitiService>[])
        .where((s) => _matches('${s.name} ${s.description} ${s.endpoint}'))
        .toList();
    final resourceList = (resources.valueOrNull ?? const <MyResource>[])
        .where((r) => _matches('${r.name} ${r.to} ${r.note}'))
        .toList();
    final pamList = (pam.valueOrNull ?? const <PamEntry>[])
        .where((e) => _matches('${e.name} ${e.hostname}'))
        .toList();

    final anyLoading = apps.isLoading ||
        ziti.isLoading ||
        resources.isLoading ||
        pam.isLoading;
    final nothingToShow = appList.isEmpty &&
        zitiList.isEmpty &&
        resourceList.isEmpty &&
        pamList.isEmpty;

    final body = RefreshIndicator(
      onRefresh: () async => _refresh(),
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          TextField(
            decoration: const InputDecoration(
              prefixIcon: Icon(Icons.search),
              hintText: 'Search apps and resources',
              isDense: true,
              border: OutlineInputBorder(),
            ),
            onChanged: (v) => setState(() => _query = v.trim().toLowerCase()),
          ),
          const SizedBox(height: 12),

          if (anyLoading && nothingToShow)
            const Padding(
              padding: EdgeInsets.all(24),
              child: Center(child: CircularProgressIndicator()),
            ),

          if (appList.isNotEmpty)
            _Section(
              icon: Icons.apps,
              color: const Color(0xFF2563EB),
              title: 'Sign in',
              children: [for (final a in appList) _AppTile(app: a)],
            ),

          if (zitiList.isNotEmpty)
            _Section(
              icon: Icons.verified_user,
              color: const Color(0xFF15803D),
              title: 'Apps over the network',
              children: [for (final s in zitiList) _ZitiTile(service: s)],
            ),

          if (resourceList.isNotEmpty)
            _Section(
              icon: Icons.lan,
              color: const Color(0xFF7C3AED),
              title: 'Connect over the network',
              children: [for (final r in resourceList) _ResourceTile(resource: r)],
            ),

          if (pamList.isNotEmpty)
            _Section(
              icon: Icons.vpn_key,
              color: const Color(0xFFB45309),
              title: 'Privileged access',
              children: [for (final e in pamList) _PamTile(entry: e)],
            ),

          if (!anyLoading && nothingToShow)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 32),
              child: Center(
                child: Text(
                  'Nothing is assigned to you yet.\n'
                  'Ask an administrator for access.',
                  textAlign: TextAlign.center,
                ),
              ),
            ),

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
    );

    if (!widget.showAppBar) return body;
    return Scaffold(
      appBar: AppBar(title: const Text('My Access')),
      body: body,
    );
  }
}

class _Section extends StatelessWidget {
  const _Section({
    required this.icon,
    required this.color,
    required this.title,
    required this.children,
  });

  final IconData icon;
  final Color color;
  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(bottom: 8, left: 4),
          child: Row(
            children: [
              Icon(icon, size: 18, color: color),
              const SizedBox(width: 6),
              Text(title,
                  style: const TextStyle(
                      fontWeight: FontWeight.w600, fontSize: 16)),
            ],
          ),
        ),
        for (final child in children)
          Padding(padding: const EdgeInsets.only(bottom: 8), child: child),
        const Divider(height: 24),
      ],
    );
  }
}

/// Messaging takes the messenger captured BEFORE any await rather than a
/// BuildContext, so nothing reaches for the element tree across an async gap.
void _say(ScaffoldMessengerState messenger, String message) {
  messenger.showSnackBar(SnackBar(content: Text(message)));
}

Future<void> _openUrl(
    ScaffoldMessengerState messenger, String url, String name) async {
  final uri = Uri.tryParse(url);
  if (uri == null) {
    _say(messenger, 'Could not open $name: bad address');
    return;
  }
  if (!await launchUrl(uri, mode: LaunchMode.externalApplication)) {
    _say(messenger, 'Could not open $name');
  }
}

class _AppTile extends StatelessWidget {
  const _AppTile({required this.app});
  final PortalApp app;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        leading: const CircleAvatar(
          backgroundColor: Color(0xFFDBEAFE),
          child: Icon(Icons.apps, color: Color(0xFF2563EB)),
        ),
        title:
            Text(app.name, style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: app.description.isEmpty ? null : Text(app.description),
        trailing: app.canOpen
            ? TextButton(
                onPressed: () => _openUrl(
                    ScaffoldMessenger.of(context), app.url, app.name),
                child: const Text('Open'),
              )
            : null,
      ),
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
      _say(
        messenger,
        where.isEmpty
            ? 'Connected to ${service.name}'
            : 'Connect ${service.name} at $where',
      );
    } catch (e) {
      _say(messenger, 'Could not connect to ${service.name}: $e');
    }
  }
}

class _ResourceTile extends ConsumerWidget {
  const _ResourceTile({required this.resource});
  final MyResource resource;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final ready = resource.isReady;
    return Card(
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: ready ? const Color(0xFFEDE9FE) : const Color(0xFFF1F5F9),
          child: Icon(_iconFor(resource.kind),
              color: ready ? const Color(0xFF7C3AED) : Colors.black45),
        ),
        title: Text(resource.name,
            style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (resource.endpoint.isNotEmpty)
              Text(resource.endpoint,
                  style: const TextStyle(fontSize: 12, color: Colors.black54)),
            if (resource.note.isNotEmpty)
              Text(resource.note, style: const TextStyle(fontSize: 12)),
          ],
        ),
        trailing: resource.actionLabel.isEmpty
            ? null
            : TextButton(
                onPressed: () => _act(context, ref),
                child: Text(resource.actionLabel),
              ),
      ),
    );
  }

  static IconData _iconFor(String kind) => switch (kind) {
        'web' => Icons.public,
        'remote_desktop' => Icons.desktop_windows,
        'ssh' => Icons.terminal,
        'database' => Icons.storage,
        _ => Icons.lan,
      };

  Future<void> _act(BuildContext context, WidgetRef ref) async {
    final messenger = ScaffoldMessenger.of(context);
    switch (resource.actionKind) {
      case 'open_url':
        await _openUrl(messenger, resource.actionUrl, resource.name);
      case 'broker_connect':
        try {
          final result = await ref
              .read(engineClientProvider)
              .pamConnect(resource.actionTarget);
          if (result.url.isNotEmpty) {
            await _openUrl(messenger, result.url, resource.name);
          } else {
            _say(messenger, 'Connected to ${resource.name}');
          }
        } catch (e) {
          _say(messenger, 'Could not connect to ${resource.name}: $e');
        }
      case 'request':
        try {
          await ref.read(engineClientProvider).pamRequest(
              resource.actionTarget, 'Requested from the OpenIDX app');
          _say(messenger, 'Request sent for ${resource.name}');
          ref.invalidate(myRequestsProvider);
        } catch (e) {
          _say(messenger, 'Could not send the request: $e');
        }
      default:
        _say(messenger, 'Nothing to do for ${resource.name}');
    }
  }
}

class _PamTile extends ConsumerWidget {
  const _PamTile({required this.entry});
  final PamEntry entry;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Card(
      child: ListTile(
        leading: const CircleAvatar(
          backgroundColor: Color(0xFFFEF3C7),
          child: Icon(Icons.vpn_key, color: Color(0xFFB45309)),
        ),
        title: Text(entry.name,
            style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Text([
          if (entry.entryType.isNotEmpty) entry.entryType.toUpperCase(),
          if (entry.hostname.isNotEmpty) entry.hostname,
        ].join(' · ')),
        trailing: TextButton(
          onPressed: () => entry.requireApproval
              ? _request(context, ref)
              : _connect(context, ref),
          child: Text(entry.requireApproval ? 'Request' : 'Connect'),
        ),
      ),
    );
  }

  Future<void> _connect(BuildContext context, WidgetRef ref) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      final result = await ref.read(engineClientProvider).pamConnect(entry.id);
      if (result.url.isNotEmpty) {
        await _openUrl(messenger, result.url, entry.name);
      } else {
        _say(messenger, 'Session opened for ${entry.name}');
      }
    } catch (e) {
      _say(messenger, 'Could not connect to ${entry.name}: $e');
    }
  }

  Future<void> _request(BuildContext context, WidgetRef ref) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      await ref
          .read(engineClientProvider)
          .pamRequest(entry.id, 'Requested from the OpenIDX app');
      _say(messenger, 'Request sent for ${entry.name}');
      ref.invalidate(myRequestsProvider);
    } catch (e) {
      _say(messenger, 'Could not send the request: $e');
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
