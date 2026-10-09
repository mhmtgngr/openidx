import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/api/notifications.dart';
import 'package:openidx_client/mobile/ntfy_inbox.dart';

/// Push approvals reach the phone over the user's ntfy topic. These pin the
/// parsing of ntfy's JSON stream, the `since` bookkeeping that keeps a
/// challenge from opening twice, and that the poller asks the right URL
/// without the OpenIDX bearer token.
///
/// > Runs in CI via `.github/workflows/client-mobile-build.yml` (`flutter test`).

String msg(String id, {String? click, String event = 'message'}) => jsonEncode({
      'id': id,
      'time': 1791500000,
      'event': event,
      'topic': 'oidx-abc',
      'title': 'Authentication request',
      if (click != null) 'click': click,
    });

class _FakeAdapter implements HttpClientAdapter {
  _FakeAdapter(this.body);
  String body;
  final requests = <RequestOptions>[];

  @override
  Future<ResponseBody> fetch(RequestOptions options, Stream<Uint8List>? requestStream,
      Future<void>? cancelFuture) async {
    requests.add(options);
    return ResponseBody.fromString(body, 200,
        headers: {Headers.contentTypeHeader: ['application/x-ndjson']});
  }

  @override
  void close({bool force = false}) {}
}

void main() {
  group('approveChallengeFromNtfyLine', () {
    test('a challenge message yields its id', () {
      expect(approveChallengeFromNtfyLine(msg('m1', click: 'openidx://approve/ch-123')), 'ch-123');
    });
    test('keepalives, opens and other links are ignored', () {
      expect(approveChallengeFromNtfyLine(msg('k', event: 'keepalive')), isNull);
      expect(approveChallengeFromNtfyLine(msg('o', event: 'open')), isNull);
      expect(approveChallengeFromNtfyLine(msg('m2')), isNull);
      expect(approveChallengeFromNtfyLine(msg('m3', click: 'https://example.com/x')), isNull);
      expect(approveChallengeFromNtfyLine(msg('m4', click: 'openidx://enroll?code=X')), isNull);
    });
    test('garbage and blank lines are ignored', () {
      expect(approveChallengeFromNtfyLine(''), isNull);
      expect(approveChallengeFromNtfyLine('not json'), isNull);
      expect(approveChallengeFromNtfyLine('[1,2]'), isNull);
    });
  });

  test('lastNtfyMessageId skips non-message events', () {
    expect(lastNtfyMessageId([msg('a', click: 'x'), msg('b'), msg('k', event: 'keepalive')]), 'b');
    expect(lastNtfyMessageId(['', 'junk']), isNull);
  });

  group('PushConfig', () {
    test('reads the ntfy server and topic the server sends', () {
      final c = PushConfig.fromJson(
          {'enabled': true, 'base_url': 'https://openidx.tdv.org/ntfy', 'topic': 'oidx-abc'});
      expect(c.canListen, isTrue);
      expect(c.baseUrl, 'https://openidx.tdv.org/ntfy');
    });
    test('a server without ntfy gives nothing to listen to', () {
      expect(PushConfig.fromJson({'enabled': false}).canListen, isFalse);
    });
  });

  group('NtfyTopicPoller', () {
    test('polls the topic anonymously and moves since forward', () async {
      final adapter = _FakeAdapter(
          [msg('m1', click: 'openidx://approve/ch-1'), msg('m2'), msg('m3', click: 'openidx://approve/ch-2')]
              .join('\n'));
      final dio = Dio()..httpClientAdapter = adapter;
      final p = NtfyTopicPoller(baseUrl: 'https://openidx.tdv.org/ntfy/', topic: 'oidx-abc', dio: dio);

      expect(await p.poll(), ['ch-1', 'ch-2']);
      final first = adapter.requests.single;
      expect(first.uri.toString(),
          'https://openidx.tdv.org/ntfy/oidx-abc/json?poll=1&since=$ntfyCatchUp');
      expect(first.headers.containsKey('Authorization'), isFalse);

      adapter.body = '';
      expect(await p.poll(), isEmpty);
      expect(adapter.requests.last.uri.queryParameters['since'], 'm3');

      p.rewind();
      await p.poll();
      expect(adapter.requests.last.uri.queryParameters['since'], ntfyCatchUp);
    });
  });
}
