/// Data models for the OpenIDX engine control API.
///
/// The JSON tags below MUST match the shapes emitted by the Go
/// `openidx-agent serve` control server exactly. See the ENGINE CONTROL
/// CONTRACT in `client/README.md`.
library;

/// Helpers that tolerate the loose JSON typing that comes off `dart:convert`.
int _asInt(Object? v, [int fallback = 0]) {
  if (v is int) return v;
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v) ?? fallback;
  return fallback;
}

double _asDouble(Object? v, [double fallback = 0]) {
  if (v is double) return v;
  if (v is num) return v.toDouble();
  if (v is String) return double.tryParse(v) ?? fallback;
  return fallback;
}

bool _asBool(Object? v, [bool fallback = false]) {
  if (v is bool) return v;
  if (v is String) return v.toLowerCase() == 'true';
  if (v is num) return v != 0;
  return fallback;
}

String _asString(Object? v, [String fallback = '']) {
  if (v == null) return fallback;
  if (v is String) return v;
  return v.toString();
}

/// What the server currently allows this device to do, from `GET /device-state`.
///
/// The client used to know only what was on disk — enrolled, has a Ziti
/// identity, signed in — which cannot tell a device that is waiting for an
/// administrator from one that is working, or either from one that has been
/// revoked. A device that is waiting then looks, to its user, exactly like a
/// device that is broken. These four fields are the server's answer; the words
/// shown to the user are the UI's job (see DeviceStateBanner).
class DeviceState {
  const DeviceState({
    required this.enrolled,
    required this.state,
    required this.deviceTrusted,
    required this.serverReachable,
    this.error = '',
  });

  /// Is there an agent identity on this device at all (local truth).
  final bool enrolled;

  /// `pending`, `active`, `suspended`, `revoked`, `not_enrolled`, or `unknown`
  /// when the server could not be asked.
  final String state;

  /// The IAM device-trust flag the overlay's `#device-trusted` follows. Only
  /// ever true alongside an `active` state.
  final bool deviceTrusted;

  /// False means "I could not ask", which must never be rendered as a refusal.
  final bool serverReachable;

  /// Why the ask failed, when it did.
  final String error;

  factory DeviceState.fromJson(Map<String, dynamic> json) => DeviceState(
        enrolled: _asBool(json['enrolled']),
        state: _asString(json['state'], 'unknown'),
        deviceTrusted: _asBool(json['device_trusted']),
        serverReachable: _asBool(json['server_reachable']),
        error: _asString(json['error']),
      );

  static const DeviceState unknown = DeviceState(
    enrolled: false,
    state: 'unknown',
    deviceTrusted: false,
    serverReachable: false,
  );

  /// True when the device is enrolled and the server has not yet approved it.
  bool get waitingForApproval => state == 'pending';

  /// True when the device works but has not earned device trust (Tier 1).
  bool get tierOne => state == 'active' && !deviceTrusted;

  /// True when the device has earned device trust (Tier 2).
  bool get tierTwo => state == 'active' && deviceTrusted;

  /// True when an administrator has taken this device off the fleet.
  bool get revoked => state == 'revoked';
}

/// `GET /status`
class AgentStatus {
  const AgentStatus({
    required this.enrolled,
    required this.agentId,
    required this.deviceId,
    required this.serverUrl,
    required this.zitiEnrolled,
    required this.loggedIn,
    required this.userSub,
    required this.userEmail,
    required this.tokenExpiry,
    required this.tokenExpired,
  });

  final bool enrolled;
  final String agentId;
  final String deviceId;
  final String serverUrl;
  final bool zitiEnrolled;
  final bool loggedIn;
  final String userSub;
  final String userEmail;
  final int tokenExpiry;
  final bool tokenExpired;

  factory AgentStatus.fromJson(Map<String, dynamic> json) => AgentStatus(
        enrolled: _asBool(json['enrolled']),
        agentId: _asString(json['agent_id']),
        deviceId: _asString(json['device_id']),
        serverUrl: _asString(json['server_url']),
        zitiEnrolled: _asBool(json['ziti_enrolled']),
        loggedIn: _asBool(json['logged_in']),
        userSub: _asString(json['user_sub']),
        userEmail: _asString(json['user_email']),
        tokenExpiry: _asInt(json['token_expiry']),
        tokenExpired: _asBool(json['token_expired']),
      );

  /// A conservative "not enrolled / not logged in" default used before the
  /// first successful poll so the UI has something to render.
  static const AgentStatus unknown = AgentStatus(
    enrolled: false,
    agentId: '',
    deviceId: '',
    serverUrl: '',
    zitiEnrolled: false,
    loggedIn: false,
    userSub: '',
    userEmail: '',
    tokenExpiry: 0,
    tokenExpired: false,
  );
}

/// `POST /login`
class User {
  const User({required this.sub, required this.email, required this.exp});

  final String sub;
  final String email;
  final int exp;

  factory User.fromJson(Map<String, dynamic> json) => User(
        sub: _asString(json['sub']),
        email: _asString(json['email']),
        exp: _asInt(json['exp']),
      );
}

/// `POST /enroll`
class EnrollResult {
  const EnrollResult({
    required this.agentId,
    required this.deviceId,
    required this.serverUrl,
    required this.zitiIdentity,
  });

  final String agentId;
  final String deviceId;
  final String serverUrl;
  final String zitiIdentity;

  factory EnrollResult.fromJson(Map<String, dynamic> json) => EnrollResult(
        agentId: _asString(json['agent_id']),
        deviceId: _asString(json['device_id']),
        serverUrl: _asString(json['server_url']),
        zitiIdentity: _asString(json['ziti_identity']),
      );
}

/// One row of the posture assessment.
class PostureCheck {
  const PostureCheck({
    required this.type,
    required this.severity,
    required this.status,
    required this.score,
    required this.message,
    this.unsupported = false,
  });

  final String type;
  final String severity;
  final String status;
  final double score;
  final String message;

  /// The engine has no implementation of this check for this operating system,
  /// so [status] describes the build and not the device. Seven of the ten
  /// checks are in this position on Android and iOS.
  final bool unsupported;

  factory PostureCheck.fromJson(Map<String, dynamic> json) => PostureCheck(
        type: _asString(json['type']),
        severity: _asString(json['severity']),
        status: _asString(json['status']),
        score: _asDouble(json['score']),
        message: _asString(json['message']),
        unsupported: _asBool(json['unsupported']),
      );
}

/// `GET /posture`
class Posture {
  const Posture({
    required this.compliant,
    required this.passed,
    required this.failed,
    required this.warned,
    required this.errored,
    required this.ranAt,
    required this.checks,
    this.unsupported = 0,
  });

  final bool compliant;
  final int passed;
  final int failed;
  final int warned;
  final int errored;
  final String ranAt;
  final List<PostureCheck> checks;

  /// How many checks could not run on this device at all. Separate from
  /// [warned] because it is not a fact about the device: it says the engine
  /// has no implementation here, and the engine withholds [compliant] whenever
  /// it is non-zero.
  final int unsupported;

  /// Whether this build could examine the device at all. False on a platform
  /// where nothing ran — which is the honest answer to "is my phone healthy?"
  /// from a client that cannot tell.
  bool get assessable => (passed + failed + warned + errored) > 0;

  factory Posture.fromJson(Map<String, dynamic> json) {
    final rawChecks = json['checks'];
    final checks = <PostureCheck>[];
    if (rawChecks is List) {
      for (final c in rawChecks) {
        if (c is Map<String, dynamic>) {
          checks.add(PostureCheck.fromJson(c));
        }
      }
    }
    return Posture(
      compliant: _asBool(json['compliant']),
      passed: _asInt(json['passed']),
      failed: _asInt(json['failed']),
      warned: _asInt(json['warned']),
      errored: _asInt(json['errored']),
      ranAt: _asString(json['ran_at']),
      checks: checks,
      unsupported: _asInt(json['unsupported']),
    );
  }

  static const Posture empty = Posture(
    compliant: false,
    passed: 0,
    failed: 0,
    warned: 0,
    errored: 0,
    unsupported: 0,
    ranAt: '',
    checks: <PostureCheck>[],
  );
}

/// One entry from `GET /pam/entries`.
class PamEntry {
  const PamEntry({
    required this.id,
    required this.name,
    required this.entryType,
    required this.requireApproval,
    required this.recordSession,
    required this.reachMode,
    required this.hostname,
    required this.port,
  });

  final String id;
  final String name;
  final String entryType;
  final bool requireApproval;
  final bool recordSession;
  final String reachMode;
  final String hostname;
  final int port;

  factory PamEntry.fromJson(Map<String, dynamic> json) => PamEntry(
        id: _asString(json['id']),
        name: _asString(json['name']),
        entryType: _asString(json['entry_type']),
        requireApproval: _asBool(json['require_approval']),
        recordSession: _asBool(json['record_session']),
        reachMode: _asString(json['reach_mode']),
        hostname: _asString(json['hostname']),
        port: _asInt(json['port']),
      );
}

/// `POST /pam/connect`
class PamConnectResult {
  const PamConnectResult({
    required this.launchType,
    required this.connectUrl,
    required this.url,
  });

  final String launchType;
  final String connectUrl;
  final String url;

  factory PamConnectResult.fromJson(Map<String, dynamic> json) =>
      PamConnectResult(
        launchType: _asString(json['launch_type']),
        connectUrl: _asString(json['connect_url']),
        url: _asString(json['url']),
      );

  /// Best-effort URL to hand to `url_launcher`: prefer `connect_url`, fall
  /// back to the generic `url` field.
  String get launchTarget => connectUrl.isNotEmpty ? connectUrl : url;
}
