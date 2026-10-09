import 'dart:async';
import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../api/notifications.dart';
import '../state/api_providers.dart';
import '../ui/screens/mobile/push_approve_screen.dart';
import 'deep_links.dart';

// Push approvals reach this phone over the user's ntfy topic: the server
// publishes every challenge there with a click link openidx://approve/<id>
// (internal/identity/pushmfa_ntfy.go). Nothing in the app used to listen, so
// a sign-in waiting for approval never reached the phone. The inbox below
// polls the topic while the app is in the foreground and opens the approve
// screen for each new challenge. ntfy keeps messages for a while, so asking
// for everything since the last one seen also catches a challenge that was
// sent while the app was closed and the person opened it to approve.

/// How often the topic is polled while the app is in the foreground.
const ntfyPollInterval = Duration(seconds: 3);

/// How far back the first poll after start or resume looks. A push challenge
/// expires in about a minute, so anything older could not be approved anyway.
const ntfyCatchUp = '2m';

/// The challenge id a ntfy message line asks the person to approve, or null.
///
/// [line] is one line of ntfy's JSON stream. Only `message` events whose click
/// link is an `openidx://approve/<id>` deep link count; keepalives, opens and
/// any other message are ignored.
String? approveChallengeFromNtfyLine(String line) {
  final trimmed = line.trim();
  if (trimmed.isEmpty) return null;
  Object? decoded;
  try {
    decoded = jsonDecode(trimmed);
  } on FormatException {
    return null;
  }
  if (decoded is! Map<String, dynamic>) return null;
  if (decoded['event'] != 'message') return null;
  final click = decoded['click'];
  if (click is! String || click.isEmpty) return null;
  final uri = Uri.tryParse(click);
  if (uri == null) return null;
  final link = OpenidxDeepLink.parse(uri);
  return link is ApproveLink ? link.challengeId : null;
}

/// The id of the last message in a batch of ntfy JSON lines, used as the next
/// poll's `since` so nothing is fetched twice.
String? lastNtfyMessageId(Iterable<String> lines) {
  String? last;
  for (final line in lines) {
    try {
      final m = jsonDecode(line.trim());
      if (m is Map<String, dynamic> && m['event'] == 'message' && m['id'] is String) {
        last = m['id'] as String;
      }
    } on FormatException {
      continue;
    }
  }
  return last;
}

/// Polls one ntfy topic. Uses its own [Dio] so the OpenIDX bearer token is
/// never sent to the ntfy server: topics are read anonymously, and a topic is
/// an unguessable HMAC of the user id.
class NtfyTopicPoller {
  NtfyTopicPoller({required this.baseUrl, required this.topic, Dio? dio})
      : _dio = dio ?? Dio(BaseOptions(connectTimeout: const Duration(seconds: 5)));

  final String baseUrl;
  final String topic;
  final Dio _dio;
  String _since = ntfyCatchUp;

  /// Starts the next poll from [ntfyCatchUp] again, after the app was away.
  void rewind() => _since = ntfyCatchUp;

  /// Fetches the messages since the last poll and returns the challenge ids
  /// they ask the person to approve, oldest first.
  Future<List<String>> poll() async {
    final base = baseUrl.endsWith('/') ? baseUrl.substring(0, baseUrl.length - 1) : baseUrl;
    final resp = await _dio.get<String>(
      '$base/${Uri.encodeComponent(topic)}/json',
      queryParameters: {'poll': '1', 'since': _since},
      options: Options(responseType: ResponseType.plain),
    );
    final lines = const LineSplitter().convert(resp.data ?? '');
    final last = lastNtfyMessageId(lines);
    if (last != null) _since = last;
    return [
      for (final l in lines)
        if (approveChallengeFromNtfyLine(l) case final id?) id,
    ];
  }
}

/// Wraps the signed-in shell: listens for push approvals on the user's ntfy
/// topic while the app is in the foreground, and routes `openidx://approve`
/// links, and opens the approve screen for each challenge once.
class NtfyInbox extends ConsumerStatefulWidget {
  const NtfyInbox({super.key, required this.child});

  final Widget child;

  @override
  ConsumerState<NtfyInbox> createState() => _NtfyInboxState();
}

class _NtfyInboxState extends ConsumerState<NtfyInbox> with WidgetsBindingObserver {
  NtfyTopicPoller? _poller;
  Timer? _timer;
  bool _polling = false;
  StreamSubscription<OpenidxDeepLink>? _links;
  final _opened = <String>{};

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    final links = ref.read(deepLinkServiceProvider);
    unawaited(links.init());
    _links = links.links.listen((link) {
      if (link is ApproveLink) _open(link.challengeId);
    });
    unawaited(_start());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _timer?.cancel();
    _links?.cancel();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _poller?.rewind();
      unawaited(_start());
    } else if (state == AppLifecycleState.paused) {
      _timer?.cancel();
      _timer = null;
    }
  }

  Future<void> _start() async {
    if (_poller == null) {
      PushConfig cfg;
      try {
        cfg = await ref.read(notificationsApiProvider).pushConfig();
      } catch (_) {
        return; // offline or signed out; the next resume tries again
      }
      if (!cfg.canListen || !mounted) return;
      _poller = NtfyTopicPoller(baseUrl: cfg.baseUrl, topic: cfg.topic);
    }
    _timer?.cancel();
    _timer = Timer.periodic(ntfyPollInterval, (_) => _tick());
    unawaited(_tick());
  }

  Future<void> _tick() async {
    final poller = _poller;
    if (poller == null || _polling) return;
    _polling = true;
    try {
      for (final id in await poller.poll()) {
        _open(id);
      }
    } catch (_) {
      // A missed poll is retried on the next tick.
    } finally {
      _polling = false;
    }
  }

  void _open(String challengeId) {
    if (!mounted || !_opened.add(challengeId)) return;
    Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => PushApproveScreen(challengeId: challengeId)),
    );
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
