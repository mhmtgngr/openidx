import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../api/api_client.dart';
import '../../../api/mfa.dart';
import '../../../state/api_providers.dart';

/// Number-match push approval. Reached via the `openidx://approve/<challengeId>`
/// deep link (or a push tap). Shows the sign-in context and asks the person to
/// type the two-digit number the sign-in screen shows; the server approves only
/// when that number matches. The person can also deny the request, or report
/// it as a sign-in they did not start. Backed by the push verify endpoint.
class PushApproveScreen extends ConsumerStatefulWidget {
  const PushApproveScreen({super.key, required this.challengeId});

  final String challengeId;

  @override
  ConsumerState<PushApproveScreen> createState() => _PushApproveScreenState();
}

class _PushApproveScreenState extends ConsumerState<PushApproveScreen> {
  late Future<PushChallenge> _challenge;
  final _code = TextEditingController();
  bool _submitting = false;

  /// Set when the server says the request can no longer be answered, so the
  /// screen stops offering answers that cannot work.
  bool _closed = false;

  /// Set when the server says this device may not approve this request. A
  /// deny or report can still be recorded, so only Approve is taken away.
  bool _approveRefused = false;

  /// Why the server refused the last answer, in words the person can act on.
  String? _problem;

  @override
  void initState() {
    super.initState();
    _challenge =
        ref.read(mfaApiProvider).pushChallenge(widget.challengeId);
  }

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  bool get _canApprove =>
      !_submitting &&
      !_closed &&
      !_approveRefused &&
      isPushChallengeCode(_code.text);

  Future<void> _decide(PushDecision decision) async {
    setState(() {
      _submitting = true;
      _problem = null;
    });
    try {
      await ref.read(mfaApiProvider).pushVerify(
            challengeId: widget.challengeId,
            decision: decision,
            challengeCode: decision == PushDecision.approve ? _code.text : null,
          );
      if (!mounted) return;
      final label = switch (decision) {
        PushDecision.approve => 'Approved',
        PushDecision.deny => 'Denied',
        PushDecision.report => 'Reported',
      };
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(label)));
      Navigator.of(context).maybePop();
    } on ApiException catch (e) {
      if (mounted) _showRefusal(e);
    } catch (e) {
      if (mounted) setState(() => _problem = 'Could not send your answer: $e');
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  /// Explains a refusal from the push verify endpoint. The statuses and error
  /// texts matched here are the ones handleVerifyPushChallenge and
  /// VerifyPushMFAChallenge return (internal/identity/handlers_mfa.go and
  /// pushmfa.go): the server sends no error codes, only these.
  void _showRefusal(ApiException e) {
    setState(() {
      if (e.status == 400 && e.message.contains('too many attempts')) {
        // The server denies the request after too many wrong numbers.
        _problem = 'Too many wrong numbers, so this sign-in request was '
            'denied. Start the sign-in again if it was you.';
        _closed = true;
      } else if (e.status == 400 &&
          e.message.startsWith('invalid challenge code')) {
        // The request stays open, so the field is cleared for the right
        // number to be typed in fresh.
        _problem = 'That number does not match the one on the sign-in '
            'screen. Check it and type it again.';
        _code.clear();
      } else if (e.status == 403) {
        _problem = 'This sign-in cannot be approved from this device. The '
            'request belongs to another account, or this device is no longer '
            'allowed to approve sign-ins.';
        _approveRefused = true;
      } else if (e.status == 400) {
        // Expired, already answered, or no longer known to the server.
        _problem = 'This sign-in request has expired or was already '
            'answered. Start the sign-in again if it was you.';
        _closed = true;
      } else if (e.status == 401) {
        _problem = 'You are signed out of OpenIDX on this phone. Sign in '
            'again, then answer the request.';
      } else {
        _problem = 'Could not send your answer: ${e.message}. Try again.';
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Approve sign-in')),
      body: FutureBuilder<PushChallenge>(
        future: _challenge,
        builder: (context, snap) {
          if (snap.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snap.hasError) {
            return Center(child: Text('Could not load challenge: ${snap.error}'));
          }
          final c = snap.data!;
          return _body(context, c);
        },
      ),
    );
  }

  Widget _body(BuildContext context, PushChallenge c) {
    final canAnswer = !_submitting && !_closed;
    // A ListView rather than a fixed Column, so the keyboard the number field
    // opens cannot push the buttons off a small screen.
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        _contextCard(context, c),
        const SizedBox(height: 24),
        const Text('Type the number shown on the sign-in screen',
            textAlign: TextAlign.center),
        const SizedBox(height: 12),
        Center(
          child: SizedBox(
            width: 140,
            child: TextField(
              controller: _code,
              enabled: !_closed && !_approveRefused,
              autofocus: true,
              keyboardType: TextInputType.number,
              textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 32, letterSpacing: 8),
              inputFormatters: [
                FilteringTextInputFormatter.digitsOnly,
                LengthLimitingTextInputFormatter(2),
              ],
              decoration: const InputDecoration(hintText: '--'),
              onChanged: (_) => setState(() {}),
              onSubmitted: (_) {
                if (_canApprove) _decide(PushDecision.approve);
              },
            ),
          ),
        ),
        if (_problem != null) ...[
          const SizedBox(height: 12),
          Text(
            _problem!,
            textAlign: TextAlign.center,
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
        ],
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: _canApprove ? () => _decide(PushDecision.approve) : null,
          icon: const Icon(Icons.check),
          label: const Text('Approve'),
        ),
        const SizedBox(height: 24),
        OutlinedButton.icon(
          onPressed: canAnswer ? () => _decide(PushDecision.deny) : null,
          icon: const Icon(Icons.close),
          label: const Text('Deny'),
        ),
        const SizedBox(height: 8),
        TextButton.icon(
          onPressed: canAnswer ? () => _decide(PushDecision.report) : null,
          icon: const Icon(Icons.report_gmailerrorred),
          label: const Text('It wasn’t me — Report'),
        ),
      ],
    );
  }

  Widget _contextCard(BuildContext context, PushChallenge c) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(c.appName.isEmpty ? 'Sign-in request' : c.appName,
                style: const TextStyle(
                    fontSize: 18, fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            if (c.location.isNotEmpty) _kv(Icons.place_outlined, c.location),
            if (c.ipAddress.isNotEmpty) _kv(Icons.wifi, c.ipAddress),
            if (c.browser.isNotEmpty) _kv(Icons.web, c.browser),
            if (c.requestedAt.isNotEmpty)
              _kv(Icons.schedule, _when(context, c.requestedAt)),
          ],
        ),
      ),
    );
  }

  /// The server sends an RFC 3339 timestamp; show it in the phone's local
  /// time and format, and fall back to the raw text if it does not parse.
  String _when(BuildContext context, String raw) {
    final t = DateTime.tryParse(raw)?.toLocal();
    if (t == null) return raw;
    final l = MaterialLocalizations.of(context);
    return '${l.formatShortDate(t)} '
        '${l.formatTimeOfDay(TimeOfDay.fromDateTime(t))}';
  }

  Widget _kv(IconData icon, String value) => Padding(
        padding: const EdgeInsets.only(top: 4),
        child: Row(children: [
          Icon(icon, size: 16),
          const SizedBox(width: 8),
          Expanded(child: Text(value)),
        ]),
      );
}
