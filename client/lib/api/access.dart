import 'api_client.dart';

/// Access endpoints: the zero-trust (OpenZiti) apps the signed-in user can
/// reach over the secure network. Mirrors the web "My Network" Zero-trust apps
/// section (GET /api/v1/access/my/ziti/services).
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
