import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/engine/desktop_engine_client.dart';
import 'package:openidx_client/engine/engine_client.dart';

/// The Windows endpoint discovery, run on any host: the resolver is told it is
/// on Windows and given an environment whose LOCALAPPDATA and ProgramData are
/// temporary directories.
void main() {
  late Directory root;
  late String localAppData;
  late String programData;

  setUp(() {
    root = Directory.systemTemp.createTempSync('openidx-endpoint-');
    localAppData = '${root.path}${Platform.pathSeparator}Local';
    programData = '${root.path}${Platform.pathSeparator}ProgramData';
  });

  tearDown(() => root.deleteSync(recursive: true));

  File endpointFile(String base) {
    final sep = Platform.pathSeparator;
    return File('$base${sep}OpenIDX${sep}agent${sep}control-endpoint.json');
  }

  void writeEndpoint(String base, int port, String token) {
    endpointFile(base)
      ..createSync(recursive: true)
      ..writeAsStringSync(
          jsonEncode({'addr': '127.0.0.1:$port', 'token': token}));
  }

  EngineEndpointResolver resolverFor(Map<String, String> env) =>
      EngineEndpointResolver(environment: env, isWindows: true);

  test('reads the plain endpoint file from LOCALAPPDATA before ProgramData',
      () async {
    writeEndpoint(localAppData, 50001, 'current-engine');
    writeEndpoint(programData, 50002, 'older-engine');

    final endpoint = await resolverFor({
      'LOCALAPPDATA': localAppData,
      'ProgramData': programData,
    }).resolve();

    expect(endpoint.isUnixSocket, isFalse);
    expect(endpoint.host, '127.0.0.1');
    expect(endpoint.port, 50001);
    expect(endpoint.token, 'current-engine');
  });

  test('falls back to ProgramData when LOCALAPPDATA holds no endpoint file',
      () async {
    writeEndpoint(programData, 50002, 'older-engine');

    for (final env in [
      {'LOCALAPPDATA': localAppData, 'ProgramData': programData},
      {'ProgramData': programData},
    ]) {
      final endpoint = await resolverFor(env).resolve();
      expect(endpoint.port, 50002, reason: 'environment $env');
      expect(endpoint.token, 'older-engine', reason: 'environment $env');
    }
  });

  test('a file sealed by an older engine is an EngineException that says so',
      () async {
    // The DPAPI marker agent/internal/secretfile writes, then ciphertext.
    endpointFile(programData)
      ..createSync(recursive: true)
      ..writeAsBytesSync([
        ...ascii.encode('OPENIDX-SECRETFILE-DPAPI-v1\n'),
        0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0xff, 0xfe,
      ]);

    await expectLater(
      resolverFor({'LOCALAPPDATA': localAppData, 'ProgramData': programData})
          .resolve(),
      throwsA(isA<EngineException>()
          .having((e) => e.message, 'message', contains('older build'))),
    );
  });

  test('no endpoint file anywhere names both places it looked', () async {
    await expectLater(
      resolverFor({'LOCALAPPDATA': localAppData, 'ProgramData': programData})
          .resolve(),
      throwsA(isA<EngineException>()
          .having((e) => e.message, 'message', contains(localAppData))
          .having((e) => e.message, 'message', contains(programData))),
    );
  });

  test('after a failed connect the client reads the endpoint file again',
      () async {
    // The file left behind by an engine that was killed names a port nothing
    // listens on any more.
    final dead = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final deadPort = dead.port;
    await dead.close();
    writeEndpoint(localAppData, deadPort, 'killed-engine');

    final client = DesktopEngineClient(
      resolver: resolverFor({'LOCALAPPDATA': localAppData}),
      timeout: const Duration(seconds: 5),
    );
    addTearDown(client.close);

    await expectLater(client.status(), throwsA(isA<EngineException>()));

    // The supervisor starts a fresh engine, which publishes a new port and
    // token. The next call must reach it, with the new token.
    final fresh = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => fresh.close(force: true));
    fresh.listen((req) async {
      final authorized = req.headers.value(HttpHeaders.authorizationHeader) ==
          'Bearer fresh-engine';
      req.response
        ..statusCode = authorized ? HttpStatus.ok : HttpStatus.unauthorized
        ..headers.contentType = ContentType.json
        ..write(jsonEncode(
            authorized ? {'enrolled': true} : {'error': 'invalid control token'}));
      await req.response.close();
    });
    writeEndpoint(localAppData, fresh.port, 'fresh-engine');

    final status = await client.status();
    expect(status.enrolled, isTrue);
  });
}
