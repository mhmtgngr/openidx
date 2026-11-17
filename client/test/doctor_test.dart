import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/engine/desktop_engine_client.dart';
import 'package:openidx_client/engine/engine_client.dart';
import 'package:openidx_client/engine/models.dart';
import 'package:openidx_client/state/providers.dart';
import 'package:openidx_client/ui/screens/doctor_screen.dart';

/// The shapes `GET /doctor` and `POST /doctor/repair` emit
/// (agent/internal/doctor/report.go).
Map<String, dynamic> _report({required bool healthy, List<Map<String, dynamic>>? repairs}) => {
      'healthy': healthy,
      'support_code': healthy ? '' : 'OX1-ABCD-EFGH',
      'items': [
        {'check': 'config', 'label': 'Configuration', 'status': 'pass'},
        {'check': 'dns', 'label': 'Name lookup', 'status': healthy ? 'pass' : 'fail',
          if (!healthy) ...{
            'code': 'DNS_FAIL',
            'title': 'This device cannot look up the OpenIDX server name.',
            'action': 'Switch to another network and try again.',
          }},
        {'check': 'tunnel', 'label': 'Secure tunnel', 'status': 'skipped'},
      ],
      'repairs': repairs ?? [],
      'bundle': {'schema': 1},
    };

class _Fake {
  _Fake(this.server);
  final HttpServer server;
  final requests = <String>[];
  bool healthy = false;
  bool broken = false;

  static Future<_Fake> start() async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final fake = _Fake(server);
    server.listen((req) async {
      fake.requests.add('${req.method} ${req.uri}');
      if (fake.broken) {
        req.response.statusCode = HttpStatus.internalServerError;
        req.response.write('{"error":"doctor exploded"}');
        await req.response.close();
        return;
      }
      Object body;
      if (req.uri.path == '/doctor') {
        body = _report(healthy: fake.healthy);
      } else if (req.uri.path == '/doctor/repair' && req.method == 'POST') {
        body = _report(healthy: false, repairs: [
          {'id': 'flush_dns', 'label': 'Clear the name-lookup cache', 'outcome': 'applied', 'result': 'Done'},
          {'id': 'restart_service', 'label': 'Restart the agent', 'outcome': 'needs_elevation', 'result': 'Needs administrator rights'},
        ]);
      } else {
        req.response.statusCode = HttpStatus.notFound;
        await req.response.close();
        return;
      }
      req.response
        ..headers.contentType = ContentType.json
        ..write(jsonEncode(body));
      await req.response.close();
    });
    return fake;
  }

  DesktopEngineClient client() => DesktopEngineClient.forEndpoint(
        EngineEndpoint.tcp(host: server.address.address, port: server.port, token: 't'),
      );
}

void main() {
  late _Fake fake;
  late DesktopEngineClient client;

  setUp(() async {
    // The widget-test binding answers every HttpClient with 400; this file talks
    // to a real loopback server, as engine_client_test.dart does.
    HttpOverrides.global = null;
    fake = await _Fake.start();
    client = fake.client();
  });
  tearDown(() async {
    client.close();
    await fake.server.close(force: true);
  });

  group('DesktopEngineClient.doctor', () {
    test('asks GET /doctor in the language given and reads the verdict', () async {
      final r = await client.doctor(lang: 'tr');
      expect(fake.requests, ['GET /doctor?lang=tr']);
      expect(r.healthy, isFalse);
      expect(r.supportCode, 'OX1-ABCD-EFGH');
      expect(r.items, hasLength(3));
      expect(r.problems, hasLength(1));
      expect(r.problems.single.code, 'DNS_FAIL');
      expect(r.problems.single.action, contains('another network'));
    });

    test('fix posts to /doctor/repair and reads what each repair became', () async {
      final r = await client.doctor(fix: true);
      expect(fake.requests, ['POST /doctor/repair']);
      expect(r.repairs.map((x) => x.outcome), ['applied', 'needs_elevation']);
      expect(r.repairs.first.label, 'Clear the name-lookup cache');
    });

    test('an engine error is an EngineException with its message', () async {
      fake.broken = true;
      expect(
        () => client.doctor(),
        throwsA(isA<EngineException>().having((e) => e.status, 'status', 500)),
      );
    });
  });

  group('DoctorReport.fromJson', () {
    test('tolerates a report with nothing in it', () {
      final r = DoctorReport.fromJson(const {});
      expect(r.healthy, isFalse);
      expect(r.items, isEmpty);
      expect(r.problems, isEmpty);
    });
  });

  group('DoctorScreen', () {
    Future<_FakeEngine> pump(WidgetTester tester, _FakeEngine engine) async {
      await tester.pumpWidget(ProviderScope(
        overrides: [engineClientProvider.overrideWithValue(engine)],
        child: const MaterialApp(home: DoctorScreen()),
      ));
      await tester.pumpAndSettle();
      return engine;
    }

    final problem = DoctorReport.fromJson(_report(healthy: false));

    testWidgets('says plainly what is wrong and what to do, with a support code', (tester) async {
      await pump(tester, _FakeEngine(problem));
      expect(find.text('This device cannot look up the OpenIDX server name.'), findsOneWidget);
      expect(find.textContaining('another network'), findsOneWidget);
      expect(find.text('OX1-ABCD-EFGH'), findsOneWidget);
      expect(find.text('Try to fix'), findsOneWidget);
    });

    testWidgets('a healthy device is told so, with nothing to repair', (tester) async {
      await pump(tester, _FakeEngine(DoctorReport.fromJson(_report(healthy: true))));
      expect(find.text('No problem found'), findsOneWidget);
      expect(find.text('Try to fix'), findsNothing);
      expect(find.text('Support code'), findsNothing);
    });

    testWidgets('Try to fix shows what each repair did, including one that needs rights', (tester) async {
      final engine = _FakeEngine(problem,
          repaired: DoctorReport.fromJson(_report(healthy: false, repairs: [
            {'id': 'flush_dns', 'label': 'Clear the name-lookup cache', 'outcome': 'applied', 'result': 'Done'},
            {'id': 'restart_service', 'label': 'Restart the agent', 'outcome': 'needs_elevation', 'result': 'Needs administrator rights'},
          ])));
      await pump(tester, engine);
      await tester.tap(find.text('Try to fix'));
      await tester.pumpAndSettle();
      expect(engine.calls, [false, true]);
      expect(find.text('Clear the name-lookup cache'), findsOneWidget);
      expect(find.text('Needs administrator rights'), findsOneWidget);
    });

    testWidgets('an engine that cannot answer is shown as an error, not as a healthy device', (tester) async {
      await pump(tester, _FakeEngine(null));
      expect(find.text('The check could not run'), findsOneWidget);
      expect(find.textContaining('doctor exploded'), findsOneWidget);
      expect(find.text('No problem found'), findsNothing);
    });
  });
}

/// Answers `doctor` from canned reports; the screen calls nothing else.
class _FakeEngine implements EngineClient {
  _FakeEngine(this.report, {this.repaired});

  final DoctorReport? report;
  final DoctorReport? repaired;

  /// The `fix` flag of each call, in order.
  final calls = <bool>[];

  @override
  Future<DoctorReport> doctor({String? lang, bool fix = false}) async {
    calls.add(fix);
    final r = fix ? (repaired ?? report) : report;
    if (r == null) throw const EngineException(500, 'doctor exploded');
    return r;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
