import 'package:dio/dio.dart' show Options;

import 'api_client.dart';

/// MFA endpoints (identity service): TOTP setup/enroll/status and push
/// register/challenge/verify. Mirrors the RN app's MFA surface.
class MfaApi {
  MfaApi(this._api);
  final ApiClient _api;

  // -- TOTP -------------------------------------------------------------------

  /// `POST /api/v1/identity/mfa/totp/setup` → provisioning secret + otpauth URI.
  Future<TotpSetup> totpSetup() async {
    final json = await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/mfa/totp/setup',
    );
    return TotpSetup.fromJson(json);
  }

  /// `POST /api/v1/identity/mfa/totp/enroll` — confirm setup with a live code.
  Future<void> totpEnroll(String code) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/mfa/totp/enroll',
      data: {'code': code},
    );
  }

  /// `GET /api/v1/identity/mfa/totp/status`.
  Future<MfaStatus> totpStatus() async {
    final json = await _api.get<Map<String, dynamic>>(
      '/api/v1/identity/mfa/totp/status',
    );
    return MfaStatus.fromJson(json);
  }

  // -- Push -------------------------------------------------------------------

  /// `POST /api/v1/identity/mfa/push/register` — register this device's token.
  Future<void> registerPush({
    required String deviceToken,
    required String platform,
  }) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/mfa/push/register',
      data: {'device_token': deviceToken, 'platform': platform},
    );
  }

  /// `GET /api/v1/identity/mfa/push/challenge/{id}` — challenge context for the
  /// number-match approval screen.
  Future<PushChallenge> pushChallenge(String id) async {
    final json = await _api.get<Map<String, dynamic>>(
      '/api/v1/identity/mfa/push/challenge/$id',
    );
    return PushChallenge.fromJson(json);
  }

  /// `POST /api/v1/identity/mfa/push/verify` — approve, deny or report a push.
  ///
  /// The server reads `{challenge_id, approved, challenge_code, reported}`
  /// (PushMFAChallengeResponse in internal/identity/pushmfa.go). Approving
  /// needs [challengeCode], the two-digit number the sign-in screen shows. A
  /// deny or a report sends no number, because the person is refusing a prompt
  /// they did not start and may never have seen that screen.
  ///
  /// Completes when the server recorded the decision, and throws
  /// [ApiException] when it refused it.
  Future<void> pushVerify({
    required String challengeId,
    required PushDecision decision,
    String? challengeCode,
  }) async {
    const path = '/api/v1/identity/mfa/push/verify';
    if (decision == PushDecision.approve) {
      // The server refuses an approval without the right number and counts
      // each wrong one against the challenge, so a value that cannot be a
      // number from the sign-in screen is stopped here instead of spending
      // one of those attempts.
      if (challengeCode == null || !isPushChallengeCode(challengeCode)) {
        throw ArgumentError.value(
            challengeCode, 'challengeCode', 'approving needs two digits');
      }
      await _api.post<Object?>(path, data: {
        'challenge_id': challengeId,
        'approved': true,
        'challenge_code': challengeCode,
      });
      return;
    }

    // The server answers a recorded deny or report with 401
    // {"verified": false}. ApiClient reads every 401 as an expired session: it
    // either sends the request again, which the server refuses because the
    // challenge is already answered, or signs the person out. Either way a
    // deny that worked would look like a failure. Accepting 401 as an answer
    // for this one request avoids both.
    final reply = await _api.post<Object?>(
      path,
      data: {
        'challenge_id': challengeId,
        'approved': false,
        if (decision == PushDecision.report) 'reported': true,
      },
      options: Options(validateStatus: _isSuccessOrDenyAnswer),
    );
    if (reply is Map && reply['verified'] == false) return;
    // A 401 without the push handler's verdict comes from the token check in
    // front of the handler, so the decision was never recorded.
    final error = reply is Map ? reply['error'] : null;
    throw ApiException(401, error is String ? error : 'not signed in');
  }
}

/// Whether [status] is a success or the 401 the push verify endpoint uses to
/// say a deny or report was recorded.
bool _isSuccessOrDenyAnswer(int? status) =>
    status != null && ((status >= 200 && status < 300) || status == 401);

/// Whether [code] has the shape of a number-match code: exactly two digits, as
/// the server generates them and the sign-in screen shows them.
bool isPushChallengeCode(String code) => RegExp(r'^[0-9]{2}$').hasMatch(code);

class TotpSetup {
  const TotpSetup({
    required this.secret,
    required this.otpauthUri,
    required this.issuer,
    required this.account,
  });
  final String secret;
  final String otpauthUri;
  final String issuer;
  final String account;

  factory TotpSetup.fromJson(Map<String, dynamic> j) => TotpSetup(
        secret: (j['secret'] ?? '') as String,
        otpauthUri: (j['otpauth_uri'] ?? j['uri'] ?? '') as String,
        issuer: (j['issuer'] ?? 'OpenIDX') as String,
        account: (j['account'] ?? '') as String,
      );
}

class MfaStatus {
  const MfaStatus({required this.enabled, required this.enrolledAt});
  final bool enabled;
  final String enrolledAt;

  factory MfaStatus.fromJson(Map<String, dynamic> j) => MfaStatus(
        enabled: (j['enabled'] ?? false) as bool,
        enrolledAt: (j['enrolled_at'] ?? '') as String,
      );
}

class PushChallenge {
  const PushChallenge({
    required this.id,
    required this.appName,
    required this.location,
    required this.ipAddress,
    required this.browser,
    required this.requestedAt,
  });
  final String id;
  final String appName;
  final String location;
  final String ipAddress;
  final String browser;
  final String requestedAt;

  /// Parses `GET /api/v1/identity/mfa/push/challenge/{id}` (handleGetPushChallenge
  /// in internal/identity/handlers_mfa.go). The approval details are in its
  /// `context` object, and the request's own fields are also at the top level,
  /// which is where this falls back to. The number to match is never in this
  /// reply: the person reads it off the sign-in screen and types it in.
  factory PushChallenge.fromJson(Map<String, dynamic> j) {
    final ctx = j['context'];
    final c = ctx is Map<String, dynamic> ? ctx : const <String, dynamic>{};
    String pick(String key) {
      final v = c[key];
      if (v is String && v.isNotEmpty) return v;
      final top = j[key];
      return top is String ? top : '';
    }

    final id = j['id'];
    return PushChallenge(
      id: id is String ? id : '',
      appName: pick('app_name'),
      location: pick('location'),
      ipAddress: pick('ip_address'),
      browser: pick('browser'),
      requestedAt: pick('created_at'),
    );
  }
}

enum PushDecision { approve, deny, report }
