import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../engine/engine_client.dart';
import '../../engine/models.dart';
import '../../state/providers.dart';

/// "Why can't I connect?": runs the agent's own diagnosis on this device and
/// says, in plain words, what is wrong and what to do about it.
///
/// The verdict and its wording come from the agent (the same checks `openidx-agent
/// doctor` and the tray run); this screen only draws them. A repair button
/// appears when something failed; it asks the agent to apply the repairs that are
/// safe to repeat and then shows what became of each.
class DoctorScreen extends ConsumerStatefulWidget {
  const DoctorScreen({super.key});

  @override
  ConsumerState<DoctorScreen> createState() => _DoctorScreenState();
}

class _DoctorScreenState extends ConsumerState<DoctorScreen> {
  DoctorReport? _report;
  String? _error;
  bool _busy = false;

  /// The agent words the report in this language. Turkish and English are the
  /// ones it knows; anything else gets English.
  String get _lang =>
      Platform.localeName.toLowerCase().startsWith('tr') ? 'tr' : 'en';

  @override
  void initState() {
    super.initState();
    _run(fix: false);
  }

  Future<void> _run({required bool fix}) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final report =
          await ref.read(engineClientProvider).doctor(lang: _lang, fix: fix);
      if (!mounted) return;
      setState(() => _report = report);
    } on EngineException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final report = _report;
    return Scaffold(
      appBar: AppBar(title: const Text("Why can't I connect?")),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          if (_busy && report == null)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 48),
              child: Center(child: CircularProgressIndicator()),
            ),
          if (_error != null && report == null) _ErrorCard(message: _error!),
          if (report != null) ..._reportBody(context, report),
          const SizedBox(height: 16),
          Row(
            children: [
              OutlinedButton.icon(
                onPressed: _busy ? null : () => _run(fix: false),
                icon: const Icon(Icons.refresh),
                label: Text(report == null ? 'Check' : 'Check again'),
              ),
              const SizedBox(width: 12),
              if (report != null && !report.healthy)
                FilledButton.icon(
                  onPressed: _busy ? null : () => _run(fix: true),
                  icon: const Icon(Icons.build_outlined),
                  label: const Text('Try to fix'),
                ),
              if (_busy && report != null) ...[
                const SizedBox(width: 12),
                const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2)),
              ],
            ],
          ),
          if (_error != null && report != null) ...[
            const SizedBox(height: 12),
            _ErrorCard(message: _error!),
          ],
        ],
      ),
    );
  }

  List<Widget> _reportBody(BuildContext context, DoctorReport report) {
    final theme = Theme.of(context);
    return [
      if (report.healthy)
        Card(
          child: ListTile(
            leading: Icon(Icons.check_circle, color: theme.colorScheme.primary),
            title: const Text('No problem found'),
            subtitle: const Text(
                'This device can reach OpenIDX. If one application still does '
                'not open, tell IT which one.'),
          ),
        )
      else
        for (final p in report.problems)
          Card(
            child: ListTile(
              leading: Icon(
                p.failed ? Icons.error_outline : Icons.warning_amber_outlined,
                color: p.failed
                    ? theme.colorScheme.error
                    : theme.colorScheme.tertiary,
              ),
              title: Text(p.title.isEmpty ? p.label : p.title),
              subtitle: p.action.isEmpty ? null : Text(p.action),
            ),
          ),
      if (report.repairs.isNotEmpty) ...[
        const SizedBox(height: 12),
        Text('Repairs', style: theme.textTheme.titleSmall),
        for (final r in report.repairs)
          ListTile(
            dense: true,
            leading: Icon(
              r.outcome == 'applied'
                  ? Icons.check
                  : r.outcome == 'planned'
                      ? Icons.schedule
                      : Icons.report_problem_outlined,
            ),
            title: Text(r.label),
            subtitle: Text(r.result),
          ),
      ],
      const SizedBox(height: 12),
      Text('Checks', style: theme.textTheme.titleSmall),
      for (final i in report.items)
        ListTile(
          dense: true,
          leading: Icon(_statusIcon(i.status), size: 18),
          title: Text(i.label),
          trailing: i.code.isEmpty ? null : Text(i.code),
        ),
      if (!report.healthy && report.supportCode.isNotEmpty) ...[
        const SizedBox(height: 12),
        _SupportCode(code: report.supportCode),
      ],
    ];
  }

  IconData _statusIcon(String status) {
    switch (status) {
      case 'pass':
        return Icons.check;
      case 'fail':
        return Icons.close;
      case 'warn':
        return Icons.priority_high;
      default:
        return Icons.remove;
    }
  }
}

class _SupportCode extends StatelessWidget {
  const _SupportCode({required this.code});

  final String code;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        title: const Text('Support code'),
        subtitle: SelectableText(
          code,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 16),
        ),
        trailing: IconButton(
          tooltip: 'Copy',
          icon: const Icon(Icons.copy),
          onPressed: () async {
            await Clipboard.setData(ClipboardData(text: code));
            if (context.mounted) {
              ScaffoldMessenger.of(context)
                  .showSnackBar(const SnackBar(content: Text('Copied')));
            }
          },
        ),
      ),
    );
  }
}

class _ErrorCard extends StatelessWidget {
  const _ErrorCard({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        leading: Icon(Icons.error_outline,
            color: Theme.of(context).colorScheme.error),
        title: const Text('The check could not run'),
        subtitle: Text(message),
      ),
    );
  }
}
