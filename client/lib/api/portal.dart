import 'api_client.dart';

/// Portal endpoints: the sign-in (SSO) applications assigned to the user —
/// the launcher tiles the web console shows in "My Apps & Network".
class PortalApi {
  PortalApi(this._api);
  final ApiClient _api;

  /// `GET /api/v1/identity/portal/applications` — the apps assigned to the
  /// caller, directly or through one of their groups.
  Future<List<PortalApp>> myApplications() async {
    final json =
        await _api.get<dynamic>('/api/v1/identity/portal/applications');
    final apps = json is Map<String, dynamic>
        ? (json['applications'] ?? json['data'])
        : json;
    if (apps is List) {
      return apps
          .whereType<Map<String, dynamic>>()
          .map(PortalApp.fromJson)
          .toList(growable: false);
    }
    return const [];
  }
}

/// One assigned application: a name and, when published, somewhere to open.
class PortalApp {
  const PortalApp({
    required this.id,
    required this.name,
    required this.description,
    required this.url,
    required this.protocol,
  });

  final String id;
  final String name;
  final String description;
  final String url;
  final String protocol;

  factory PortalApp.fromJson(Map<String, dynamic> j) => PortalApp(
        id: (j['id'] ?? '') as String,
        name: (j['name'] ?? '') as String,
        description: (j['description'] ?? '') as String,
        url: (j['base_url'] ?? j['url'] ?? '') as String,
        protocol: (j['protocol'] ?? '') as String,
      );

  bool get canOpen => url.isNotEmpty;
}
