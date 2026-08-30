import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/api/access.dart';
import 'package:openidx_client/api/api_client.dart';
import 'package:openidx_client/api/portal.dart';
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

/// Serves canned JSON in the shapes the backend returns, so the parsing the
/// screens depend on is exercised without a live server.
Future<(HttpServer, String)> _serve(Map<String, Object?> routes) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((req) async {
    final body = routes[req.uri.path];
    if (body == null) {
      req.response.statusCode = 404;
      await req.response.close();
      return;
    }
    req.response.headers.contentType = ContentType.json;
    req.response.write(jsonEncode(body));
    await req.response.close();
  });
  return (server, 'http://${server.address.address}:${server.port}');
}

void main() {
  test('myResources parses the server list, action and readiness', () async {
    final (server, base) = await _serve({
      '/api/v1/access/my/resources': {
        'resources': [
          {
            'id': 'r1',
            'name': 'Wiki',
            'kind': 'web',
            'from': 'Your browser',
            'to': 'wiki.example.com',
            'port': 443,
            'how': 'browser',
            'status': 'ready',
            'note': 'Opens in this browser.',
            'action': {
              'label': 'Open',
              'kind': 'open_url',
              'url': 'https://wiki.example.com',
            },
          },
          {
            'id': 'r2',
            'name': 'Prod DB',
            'kind': 'database',
            'status': 'request_access',
            'note': 'Needs approval.',
            'action': {'label': 'Request access', 'kind': 'request', 'target': 'r2'},
          },
        ],
        'summary': {'total': 2, 'ready': 1},
      },
    });
    addTearDown(() => server.close(force: true));

    final api = AccessApi(ApiClient(baseUrl: base, tokens: _EmptyTokens()));
    final resources = await api.myResources();

    expect(resources.length, 2);
    expect(resources.first.name, 'Wiki');
    expect(resources.first.isReady, isTrue);
    expect(resources.first.endpoint, 'wiki.example.com:443');
    expect(resources.first.actionKind, 'open_url');
    expect(resources.first.actionUrl, 'https://wiki.example.com');
    // A resource the user must request is still listed, with the action that
    // gets them there — never silently dropped.
    expect(resources[1].isReady, isFalse);
    expect(resources[1].actionKind, 'request');
    expect(resources[1].actionTarget, 'r2');
    // Missing numeric/string fields must not blow up parsing.
    expect(resources[1].port, 0);
    expect(resources[1].endpoint, '');
  });

  test('myResources tolerates an empty or unexpected body', () async {
    final (server, base) = await _serve({
      '/api/v1/access/my/resources': {'summary': <String, Object?>{}},
    });
    addTearDown(() => server.close(force: true));

    final api = AccessApi(ApiClient(baseUrl: base, tokens: _EmptyTokens()));
    expect(await api.myResources(), isEmpty);
  });

  test('myApplications parses assigned apps and openability', () async {
    final (server, base) = await _serve({
      '/api/v1/identity/portal/applications': {
        'applications': [
          {
            'id': 'a1',
            'name': 'Salesforce',
            'description': 'CRM',
            'base_url': 'https://sf.example.com',
            'protocol': 'saml',
          },
          {'id': 'a2', 'name': 'Internal tool'},
        ],
      },
    });
    addTearDown(() => server.close(force: true));

    final api = PortalApi(ApiClient(baseUrl: base, tokens: _EmptyTokens()));
    final apps = await api.myApplications();

    expect(apps.length, 2);
    expect(apps.first.name, 'Salesforce');
    expect(apps.first.url, 'https://sf.example.com');
    expect(apps.first.canOpen, isTrue);
    // An app with nowhere to go is still listed, just not openable.
    expect(apps[1].name, 'Internal tool');
    expect(apps[1].canOpen, isFalse);
  });

  test('myApplications accepts a bare list body', () async {
    final (server, base) = await _serve({
      '/api/v1/identity/portal/applications': [
        {'id': 'a1', 'name': 'Only app', 'url': 'https://only.example.com'},
      ],
    });
    addTearDown(() => server.close(force: true));

    final api = PortalApi(ApiClient(baseUrl: base, tokens: _EmptyTokens()));
    final apps = await api.myApplications();
    expect(apps.single.name, 'Only app');
    expect(apps.single.url, 'https://only.example.com');
  });
}
