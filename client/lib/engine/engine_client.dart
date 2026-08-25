import 'models.dart';

/// Thrown when the engine returns a non-2xx response.
class EngineException implements Exception {
  const EngineException(this.status, this.message);

  /// HTTP status code from the control server (or a synthetic code such as
  /// `0` when the socket could not be reached).
  final int status;
  final String message;

  @override
  String toString() => 'EngineException($status): $message';
}

/// Transport-agnostic contract for talking to the local `openidx-agent`
/// control server. The desktop implementation lives in
/// `desktop_engine_client.dart`; tests supply a loopback-HTTP fake.
abstract class EngineClient {
  Future<AgentStatus> status();

  Future<User> login();

  Future<void> logout();

  /// Point the engine at an OpenIDX server, persisted for later calls.
  ///
  /// Mobile-only in practice: the engine has no server on a fresh install and no
  /// CLI to set one, so [enroll] fails until this is called with the value from
  /// an `openidx://enroll?code=…&server=…` deep link (or typed by the user).
  /// Desktop is configured by `openidx-agent enroll --server …` / the installer
  /// and throws [EngineException] here.
  Future<void> setServer(String serverUrl);

  Future<EnrollResult> enroll(String code);

  Future<Posture> posture();

  Future<List<PamEntry>> pamList();

  Future<PamConnectResult> pamConnect(String entryId);

  Future<void> pamRequest(String entryId, String reason);

  /// Dials a Ziti service; returns the local address the tunnel is bound to.
  Future<String> zitiDial(String service);

  Future<void> zitiClose(String service);

  /// Release any pooled connections. No-op for stateless implementations.
  void close() {}
}
