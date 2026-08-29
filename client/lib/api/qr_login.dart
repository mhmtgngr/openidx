import 'api_client.dart';

/// "Sign in with QR" (passwordless): a signed-in phone scans the QR shown on a
/// desktop login page, then approves, and the desktop is logged in.
///
/// All calls are authenticated (the ApiClient carries the engine Bearer token),
/// which the backend requires — the approving user must be signed in.
class QrLoginApi {
  QrLoginApi(this._api);
  final ApiClient _api;

  /// `POST /api/v1/identity/passwordless/qr-login/scan` — bind the scanned
  /// session to this phone's user and fetch the desktop request context to show
  /// on the approval screen.
  Future<QrLoginContext> scan(
    String sessionToken, {
    String? deviceName,
    String? os,
    String? appVersion,
  }) async {
    final json = await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/passwordless/qr-login/scan',
      data: {
        'session_token': sessionToken,
        'mobile_info': {
          if (deviceName != null) 'device_name': deviceName,
          if (os != null) 'os': os,
          if (appVersion != null) 'app_version': appVersion,
        },
      },
    );
    return QrLoginContext.fromJson(json);
  }

  /// `POST /api/v1/identity/passwordless/qr-login/approve` — approve the sign-in.
  Future<void> approve(String sessionToken) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/passwordless/qr-login/approve',
      data: {'session_token': sessionToken},
    );
  }

  /// `POST /api/v1/identity/passwordless/qr-login/reject` — deny the sign-in.
  Future<void> reject(String sessionToken) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/passwordless/qr-login/reject',
      data: {'session_token': sessionToken},
    );
  }
}

/// The desktop context for a QR sign-in request, shown on the approval screen so
/// the user can spot an unexpected login. All fields are best-effort — the
/// backend may not populate every one.
class QrLoginContext {
  const QrLoginContext({
    required this.status,
    required this.ipAddress,
    required this.location,
    required this.device,
  });

  final String status;
  final String ipAddress;
  final String location;
  final String device;

  factory QrLoginContext.fromJson(Map<String, dynamic> j) {
    // browser_info is a free-form map on the session; pull common fields.
    final browser = (j['browser_info'] is Map)
        ? (j['browser_info'] as Map).cast<String, dynamic>()
        : const <String, dynamic>{};
    String s(Object? v) => v is String ? v : '';
    return QrLoginContext(
      status: s(j['status']),
      ipAddress: s(j['ip_address']).isNotEmpty
          ? s(j['ip_address'])
          : s(browser['ip_address']),
      location: s(j['location']).isNotEmpty
          ? s(j['location'])
          : s(browser['location']),
      device: s(browser['device']).isNotEmpty
          ? s(browser['device'])
          : s(browser['user_agent']),
    );
  }
}
