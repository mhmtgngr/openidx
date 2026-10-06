import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/api/api_client.dart';
import 'package:openidx_client/api/mfa.dart';
import 'package:openidx_client/api/token_store.dart';

/// A TokenStore that holds nothing — the client's real state on both platforms,
/// where the engine owns the session.
class _EmptyTokens implements TokenStore {
  @override
  Future<String?> accessToken() async => null;
  @override
  Future<String?> refreshToken() async => null;
  @override
  Future<String?> orgSlug() async => null;
  @override
  Future<void> save({String? access, String? refresh, String? orgSlug}) async {}
  @override
  Future<void> clear() async {}
}

/// One canned reply from the fake server.
typedef _Reply = (int status, Map<String, Object?> body);

/// A loopback server that records each JSON request body it receives and
/// answers with the status and body the identity service would. It is closed
/// when the test that started it ends.
class _Server {
  _Server._(this._server);

  final HttpServer _server;
  final requests = <(String, String, Map<String, dynamic>?)>[];

  String get base => 'http://${_server.address.address}:${_server.port}';
}

Future<_Server> _serve(_Reply reply) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  addTearDown(() => server.close(force: true));
  final s = _Server._(server);
  server.listen((req) async {
    final text = await utf8.decoder.bind(req).join();
    s.requests.add((
      req.method,
      req.uri.path,
      text.isEmpty ? null : jsonDecode(text) as Map<String, dynamic>,
    ));
    final (status, body) = reply;
    req.response.statusCode = status;
    req.response.headers.contentType = ContentType.json;
    req.response.write(jsonEncode(body));
    await req.response.close();
  });
  return s;
}

const _verifyPath = '/api/v1/identity/mfa/push/verify';

// What the identity service answers: the first three come from
// handleVerifyPushChallenge (internal/identity/handlers_mfa.go), the last from
// the token check in front of it (openIDXAuthMiddleware in service.go).
const _approved = (200, {'verified': true, 'method': 'push_mfa'});
const _denied = (
  401,
  {'verified': false, 'message': 'Challenge denied by user'},
);
const _wrongCode = (400, {'error': 'invalid challenge code'});
const _signedOut = (401, {'error': 'invalid token'});

void main() {
  var authLost = false;

  /// An MfaApi wired the way the app wires it: the Bearer token comes from the
  /// engine, which is the path where a 401 makes ApiClient send the request
  /// again.
  MfaApi api(_Server server) => MfaApi(ApiClient(
        baseUrl: server.base,
        tokens: _EmptyTokens(),
        engineTokenGetter: () async => 'access-token',
        onAuthLost: () => authLost = true,
      ));

  setUp(() => authLost = false);

  group('pushVerify sends what the server reads', () {
    test('approve sends approved:true and the two-digit code', () async {
      final server = await _serve(_approved);

      await api(server).pushVerify(
        challengeId: 'chal-1',
        decision: PushDecision.approve,
        challengeCode: '42',
      );

      expect(server.requests, hasLength(1));
      final (method, path, body) = server.requests.single;
      expect(method, 'POST');
      expect(path, _verifyPath);
      expect(body, {
        'challenge_id': 'chal-1',
        'approved': true,
        'challenge_code': '42',
      });
    });

    test('deny sends approved:false, no code and no report flag', () async {
      final server = await _serve(_denied);

      await api(server).pushVerify(
        challengeId: 'chal-1',
        decision: PushDecision.deny,
      );

      expect(server.requests.single.$3, {
        'challenge_id': 'chal-1',
        'approved': false,
      });
    });

    test('report sends approved:false with reported:true', () async {
      final server = await _serve(_denied);

      await api(server).pushVerify(
        challengeId: 'chal-1',
        decision: PushDecision.report,
      );

      expect(server.requests.single.$3, {
        'challenge_id': 'chal-1',
        'approved': false,
        'reported': true,
      });
    });

    test('the 401 that records a deny is an answer: not resent, not a sign-out',
        () async {
      final server = await _serve(_denied);

      await api(server).pushVerify(
        challengeId: 'chal-1',
        decision: PushDecision.deny,
      );

      // A resent deny is refused as "already responded", so a second request
      // here would turn a recorded deny into an error on the screen.
      expect(server.requests, hasLength(1));
      expect(authLost, isFalse);
    });
  });

  group('pushVerify refusals reach the caller', () {
    test('approve without two digits is refused before anything is sent',
        () async {
      final server = await _serve(_approved);
      final mfa = api(server);

      for (final code in [null, '', '4', '123', '4a', ' 42']) {
        await expectLater(
          mfa.pushVerify(
            challengeId: 'chal-1',
            decision: PushDecision.approve,
            challengeCode: code,
          ),
          throwsArgumentError,
          reason: 'code ${code == null ? 'null' : '"$code"'}',
        );
      }
      expect(server.requests, isEmpty);
    });

    test('a wrong number is a 400 the caller can tell apart', () async {
      final server = await _serve(_wrongCode);

      await expectLater(
        api(server).pushVerify(
          challengeId: 'chal-1',
          decision: PushDecision.approve,
          challengeCode: '17',
        ),
        throwsA(isA<ApiException>()
            .having((e) => e.status, 'status', 400)
            .having((e) => e.message, 'message', 'invalid challenge code')),
      );
    });

    test('a refused approval is not reported as an approval', () async {
      final server = await _serve(
          (403, {'error': 'this challenge belongs to another user'}));

      await expectLater(
        api(server).pushVerify(
          challengeId: 'chal-1',
          decision: PushDecision.approve,
          challengeCode: '42',
        ),
        throwsA(isA<ApiException>().having((e) => e.status, 'status', 403)),
      );
    });

    test('a deny the sign-in check refused is not reported as recorded',
        () async {
      final server = await _serve(_signedOut);

      await expectLater(
        api(server).pushVerify(
          challengeId: 'chal-1',
          decision: PushDecision.deny,
        ),
        throwsA(isA<ApiException>()
            .having((e) => e.status, 'status', 401)
            .having((e) => e.message, 'message', 'invalid token')),
      );
    });
  });

  group('PushChallenge.fromJson', () {
    // The body handleGetPushChallenge sends: the request's fields at the top
    // level, the approval details again under "context", and no code.
    final serverReply = <String, dynamic>{
      'id': 'chal-1',
      'user_id': 'user-1',
      'device_id': 'dev-1',
      'status': 'pending',
      'created_at': '2026-10-05T09:15:30.123456789Z',
      'expires_at': '2026-10-05T09:20:30.123456789Z',
      'ip_address': '203.0.113.7',
      'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0',
      'location': 'Top-level location',
      'context': {
        'app_name': 'Admin Console',
        'location': 'Berlin, Germany',
        'ip_address': '203.0.113.7',
        'browser': 'Firefox',
        'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0',
        'created_at': '2026-10-05T09:15:30.123456789Z',
        'expires_at': '2026-10-05T09:20:30.123456789Z',
      },
    };

    test('reads the context block the server sends', () {
      final c = PushChallenge.fromJson(serverReply);

      expect(c.id, 'chal-1');
      expect(c.appName, 'Admin Console');
      expect(c.location, 'Berlin, Germany');
      expect(c.ipAddress, '203.0.113.7');
      expect(c.browser, 'Firefox');
      expect(c.requestedAt, '2026-10-05T09:15:30.123456789Z');
      expect(DateTime.tryParse(c.requestedAt), isNotNull);
    });

    test('falls back to the top-level fields when context is missing or empty',
        () {
      final noContext = Map<String, dynamic>.of(serverReply)..remove('context');
      final c = PushChallenge.fromJson(noContext);
      expect(c.location, 'Top-level location');
      expect(c.ipAddress, '203.0.113.7');
      expect(c.requestedAt, '2026-10-05T09:15:30.123456789Z');
      // There is no top-level app name or browser; they stay empty rather than
      // being made up.
      expect(c.appName, isEmpty);
      expect(c.browser, isEmpty);

      final emptyLocation = Map<String, dynamic>.of(serverReply)
        ..['context'] = {'location': '', 'app_name': ''};
      expect(
          PushChallenge.fromJson(emptyLocation).location, 'Top-level location');
    });

    test('tolerates a body with none of the fields', () {
      final c = PushChallenge.fromJson(const {});
      expect(c.id, isEmpty);
      expect(c.appName, isEmpty);
      expect(c.requestedAt, isEmpty);
    });
  });

  group('isPushChallengeCode', () {
    test('accepts exactly two digits', () {
      for (final ok in ['10', '42', '99', '05']) {
        expect(isPushChallengeCode(ok), isTrue, reason: ok);
      }
    });

    test('rejects anything else', () {
      for (final bad in ['', '4', '123', '4a', ' 42', '42 ']) {
        expect(isPushChallengeCode(bad), isFalse, reason: bad);
      }
    });
  });
}
