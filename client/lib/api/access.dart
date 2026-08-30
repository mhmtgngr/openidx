import 'api_client.dart';

/// Access endpoints behind the "what can I reach" screen: the zero-trust
/// (OpenZiti) apps and the network/brokered resources the signed-in user can
/// reach. Mirrors the web "My Apps & Network" page.
class AccessApi {
  AccessApi(this._api);
  final ApiClient _api;

  /// `GET /api/v1/access/my/ziti/services` — the caller's reachable Ziti apps.
  Future<List<ZitiService>> myZitiServices() async {
    final json =
        await _api.get<dynamic>('/api/v1/access/my/ziti/services');
    final services = json is Map<String, dynamic> ? json['services'] : json;
    if (services is List) {
      return services
          .whereType<Map<String, dynamic>>()
          .map(ZitiService.fromJson)
          .toList(growable: false);
    }
    return const [];
  }

  /// `GET /api/v1/access/my/resources` — everything the user can reach that is
  /// not a plain SSO tile: published web apps, and brokered (PAM) systems they
  /// hold a grant for. The server decides inclusion with the same predicates it
  /// enforces at connect time, so this list is not a wish list.
  Future<List<MyResource>> myResources() async {
    final json = await _api.get<dynamic>('/api/v1/access/my/resources');
    final resources = json is Map<String, dynamic> ? json['resources'] : json;
    if (resources is List) {
      return resources
          .whereType<Map<String, dynamic>>()
          .map(MyResource.fromJson)
          .toList(growable: false);
    }
    return const [];
  }
}

/// One thing the user can reach, as the server describes it. `status` is the
/// server's honesty check ('ready', 'needs_setup', 'request_access'), and
/// `action` says what the client should offer — opening a URL, asking the
/// engine to connect, or filing a request.
class MyResource {
  const MyResource({
    required this.id,
    required this.name,
    required this.kind,
    required this.from,
    required this.to,
    required this.port,
    required this.how,
    required this.status,
    required this.note,
    required this.actionLabel,
    required this.actionKind,
    required this.actionUrl,
    required this.actionTarget,
  });

  final String id;
  final String name;
  final String kind;
  final String from;
  final String to;
  final int port;
  final String how;
  final String status;
  final String note;
  final String actionLabel;
  final String actionKind;
  final String actionUrl;
  final String actionTarget;

  factory MyResource.fromJson(Map<String, dynamic> j) {
    final action = (j['action'] is Map<String, dynamic>)
        ? j['action'] as Map<String, dynamic>
        : const <String, dynamic>{};
    return MyResource(
      id: (j['id'] ?? '') as String,
      name: (j['name'] ?? '') as String,
      kind: (j['kind'] ?? '') as String,
      from: (j['from'] ?? '') as String,
      to: (j['to'] ?? '') as String,
      port: (j['port'] is int) ? j['port'] as int : 0,
      how: (j['how'] ?? '') as String,
      status: (j['status'] ?? '') as String,
      note: (j['note'] ?? '') as String,
      actionLabel: (action['label'] ?? '') as String,
      actionKind: (action['kind'] ?? '') as String,
      actionUrl: (action['url'] ?? '') as String,
      actionTarget: (action['target'] ?? '') as String,
    );
  }

  bool get isReady => status == 'ready';

  /// A friendly "host:port" endpoint label, or '' when unknown.
  String get endpoint {
    if (to.isEmpty) return '';
    return port > 0 ? '$to:$port' : to;
  }
}

/// One zero-trust service the user can reach, with plain connection details.
class ZitiService {
  const ZitiService({
    required this.name,
    required this.description,
    required this.host,
    required this.port,
    required this.protocol,
  });

  final String name;
  final String description;
  final String host;
  final int port;
  final String protocol;

  factory ZitiService.fromJson(Map<String, dynamic> j) => ZitiService(
        name: (j['name'] ?? '') as String,
        description: (j['description'] ?? '') as String,
        host: (j['host'] ?? '') as String,
        port: (j['port'] is int) ? j['port'] as int : 0,
        protocol: (j['protocol'] ?? '') as String,
      );

  /// A friendly "host:port" endpoint label, or '' when unknown.
  String get endpoint {
    if (host.isEmpty) return '';
    return port > 0 ? '$host:$port' : host;
  }
}
