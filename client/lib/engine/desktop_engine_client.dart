import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'engine_client.dart';
import 'models.dart';

/// Describes where and how to reach the local control server.
///
/// Two flavours:
///  * [EngineEndpoint.unixSocket] — non-Windows: an HTTP/1.1 server bound to a
///    Unix-domain socket. No auth token; the socket's filesystem permissions
///    are the trust boundary.
///  * [EngineEndpoint.tcp] — Windows: a loopback TCP server whose address and
///    bearer token are published in
///    `%LOCALAPPDATA%\OpenIDX\agent\control-endpoint.json`.
class EngineEndpoint {
  const EngineEndpoint._({
    required this.isUnixSocket,
    this.socketPath,
    this.host,
    this.port,
    this.token,
  });

  factory EngineEndpoint.unixSocket(String path) =>
      EngineEndpoint._(isUnixSocket: true, socketPath: path);

  factory EngineEndpoint.tcp({
    required String host,
    required int port,
    required String token,
  }) =>
      EngineEndpoint._(
        isUnixSocket: false,
        host: host,
        port: port,
        token: token,
      );

  final bool isUnixSocket;
  final String? socketPath;
  final String? host;
  final int? port;
  final String? token;
}

/// Resolves the control endpoint for the current platform.
///
/// [environment] and [isWindows] default to the running process's. Tests pass
/// them to read a Windows endpoint file from a temporary directory on any host.
class EngineEndpointResolver {
  const EngineEndpointResolver({
    Map<String, String>? environment,
    bool? isWindows,
  })  : _environment = environment,
        _isWindows = isWindows;

  final Map<String, String>? _environment;
  final bool? _isWindows;

  /// The fixed socket file name used on POSIX platforms.
  static const String socketName = 'openidx-agent.sock';

  /// The first bytes of a file the engine sealed with Windows DPAPI
  /// (agent/internal/secretfile). Engines before the endpoint file became
  /// plain JSON wrote it that way, and Dart has no DPAPI binding to open it.
  static const String _sealedMagic = 'OPENIDX-SECRETFILE-DPAPI-v1\n';

  /// Non-Windows socket path: `${XDG_RUNTIME_DIR:-<tmpdir>}/openidx-agent.sock`.
  String unixSocketPath() {
    final runtimeDir = Platform.environment['XDG_RUNTIME_DIR'];
    final base = (runtimeDir != null && runtimeDir.isNotEmpty)
        ? runtimeDir
        : Directory.systemTemp.path;
    return '$base${Platform.pathSeparator}$socketName';
  }

  /// The Windows endpoint files, in the order [resolve] tries them:
  ///  1. `%LOCALAPPDATA%\OpenIDX\agent\control-endpoint.json`, where the
  ///     engine writes it for the signed-in user;
  ///  2. `%ProgramData%\OpenIDX\agent\control-endpoint.json`, where an older
  ///     engine wrote it, and where a current one writes it when it runs
  ///     without a LOCALAPPDATA (as SYSTEM, for example).
  List<File> windowsEndpointFiles() {
    final env = _environment ?? Platform.environment;
    final localAppData = env['LOCALAPPDATA'];
    final programData = env['ProgramData'];
    return [
      if (localAppData != null && localAppData.isNotEmpty)
        File(_endpointFileUnder(localAppData)),
      File(_endpointFileUnder(
        (programData != null && programData.isNotEmpty)
            ? programData
            : r'C:\ProgramData',
      )),
    ];
  }

  static String _endpointFileUnder(String base) {
    final sep = Platform.pathSeparator;
    return '$base${sep}OpenIDX${sep}agent${sep}control-endpoint.json';
  }

  /// Discover the current endpoint. On Windows this reads (and validates) the
  /// first endpoint file that exists; otherwise it returns the well-known UDS
  /// path.
  Future<EngineEndpoint> resolve() async {
    if (_isWindows ?? Platform.isWindows) {
      final files = windowsEndpointFiles();
      File? file;
      for (final candidate in files) {
        if (await candidate.exists()) {
          file = candidate;
          break;
        }
      }
      if (file == null) {
        throw EngineException(
          0,
          'control endpoint file not found: '
          '${files.map((f) => f.path).join(' or ')} '
          '(is openidx-agent running?)',
        );
      }
      final bytes = await file.readAsBytes();
      if (_startsWith(bytes, _sealedMagic)) {
        throw EngineException(
          0,
          'the openidx-agent that wrote ${file.path} is an older build that '
          'encrypts this file for its own Windows account, so this app cannot '
          'read it; update openidx-agent',
        );
      }
      final Object? decoded;
      try {
        decoded = jsonDecode(utf8.decode(bytes));
      } on FormatException {
        throw const EngineException(0, 'malformed control-endpoint.json');
      }
      if (decoded is! Map<String, dynamic>) {
        throw const EngineException(0, 'malformed control-endpoint.json');
      }
      final addr = (decoded['addr'] as String?) ?? '';
      final token = (decoded['token'] as String?) ?? '';
      final sep = addr.lastIndexOf(':');
      if (sep <= 0 || token.isEmpty) {
        throw const EngineException(0, 'invalid control-endpoint.json contents');
      }
      final host = addr.substring(0, sep);
      final port = int.tryParse(addr.substring(sep + 1)) ?? 0;
      if (port == 0) {
        throw EngineException(0, 'invalid control endpoint port in "$addr"');
      }
      return EngineEndpoint.tcp(host: host, port: port, token: token);
    }
    return EngineEndpoint.unixSocket(unixSocketPath());
  }

  static bool _startsWith(List<int> bytes, String ascii) {
    if (bytes.length < ascii.length) return false;
    for (var i = 0; i < ascii.length; i++) {
      if (bytes[i] != ascii.codeUnitAt(i)) return false;
    }
    return true;
  }
}

/// Concrete [EngineClient] speaking HTTP/1.1 to the local control server.
///
/// On non-Windows we install a `connectionFactory` on [HttpClient] that dials
/// the Unix-domain socket, so we get full HTTP semantics (headers, status,
/// chunked bodies) over the UDS for free. On Windows we dial the loopback TCP
/// address and attach `Authorization: Bearer <token>` to every request.
class DesktopEngineClient implements EngineClient {
  DesktopEngineClient({
    EngineEndpointResolver? resolver,
    Duration timeout = const Duration(seconds: 15),
  })  : _resolver = resolver ?? const EngineEndpointResolver(),
        _timeout = timeout,
        _fixedEndpoint = null;

  /// Test/override seam: construct directly against a known endpoint,
  /// bypassing platform discovery (used by loopback-HTTP tests).
  DesktopEngineClient.forEndpoint(
    EngineEndpoint endpoint, {
    Duration timeout = const Duration(seconds: 15),
  })  : _resolver = const EngineEndpointResolver(),
        _timeout = timeout,
        _fixedEndpoint = endpoint;

  final EngineEndpointResolver _resolver;
  final Duration _timeout;
  final EngineEndpoint? _fixedEndpoint;

  EngineEndpoint? _endpoint;
  HttpClient? _http;

  Future<EngineEndpoint> _endpointOrResolve() async =>
      _fixedEndpoint ?? (_endpoint ??= await _resolver.resolve());

  Future<HttpClient> _clientFor(EngineEndpoint endpoint) async {
    if (_http != null) return _http!;
    final client = HttpClient()..connectionTimeout = _timeout;
    if (endpoint.isUnixSocket) {
      final path = endpoint.socketPath!;
      // Route every connection over the Unix-domain socket regardless of the
      // (dummy) host/port we put in the request URI.
      client.connectionFactory = (uri, proxyHost, proxyPort) {
        final address =
            InternetAddress(path, type: InternetAddressType.unix);
        return Socket.startConnect(address, 0);
      };
    }
    return _http = client;
  }

  /// The URI base. For UDS we use a placeholder authority ("localhost") that
  /// the connectionFactory ignores; for TCP we use the real host:port.
  Uri _uriFor(EngineEndpoint endpoint, String path) {
    if (endpoint.isUnixSocket) {
      return Uri.parse('http://localhost$path');
    }
    return Uri.parse('http://${endpoint.host}:${endpoint.port}$path');
  }

  /// Perform a request and decode the JSON body.
  ///
  /// Throws [EngineException] on transport failure or any non-2xx response.
  Future<dynamic> _send(String method, String path, [Map<String, dynamic>? body]) async {
    final endpoint = await _endpointOrResolve();
    final client = await _clientFor(endpoint);
    final uri = _uriFor(endpoint, path);

    // A failed connect forgets the resolved endpoint so that the next call
    // reads the endpoint file again. On Windows the engine takes a new port and
    // token each time it starts, and the file of an engine that was killed
    // stays behind: the supervisor's own kill is a TerminateProcess, which
    // skips the engine's cleanup. Kept, the stale endpoint would be dialled
    // for ever, even after the supervisor started a fresh engine, and
    // waitReady would time out.
    HttpClientRequest request;
    try {
      request = await client.openUrl(method, uri).timeout(_timeout);
    } on TimeoutException {
      _endpoint = null;
      throw EngineException(0, 'timed out connecting to engine at $path');
    } on SocketException catch (e) {
      _endpoint = null;
      throw EngineException(0, 'cannot reach engine ($path): ${e.message}');
    }

    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    if (!endpoint.isUnixSocket && endpoint.token != null) {
      request.headers.set(HttpHeaders.authorizationHeader,
          'Bearer ${endpoint.token}');
    }
    if (body != null) {
      final encoded = utf8.encode(jsonEncode(body));
      request.headers.contentType = ContentType.json;
      request.headers.contentLength = encoded.length;
      request.add(encoded);
    }

    final response = await request.close().timeout(_timeout);
    final text = await response.transform(utf8.decoder).join();

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw EngineException(response.statusCode, _errorMessage(text, response));
    }
    if (text.trim().isEmpty) return null;
    return jsonDecode(text);
  }

  String _errorMessage(String text, HttpClientResponse response) {
    if (text.isNotEmpty) {
      try {
        final decoded = jsonDecode(text);
        if (decoded is Map && decoded['error'] is String) {
          return decoded['error'] as String;
        }
      } on FormatException {
        // Non-JSON body; fall through to raw text.
      }
      return text.length > 500 ? text.substring(0, 500) : text;
    }
    return 'HTTP ${response.statusCode}';
  }

  Map<String, dynamic> _asMap(dynamic v, String route) {
    if (v is Map<String, dynamic>) return v;
    throw EngineException(0, 'unexpected response shape from $route');
  }

  @override
  Future<AgentStatus> status() async =>
      AgentStatus.fromJson(_asMap(await _send('GET', '/status'), '/status'));

  @override
  Future<User> login() async =>
      User.fromJson(_asMap(await _send('POST', '/login'), '/login'));

  @override
  Future<String> loginStart() =>
      throw UnsupportedError('desktop uses login()');

  @override
  Future<User> loginFinish(String callbackUrl) =>
      throw UnsupportedError('desktop uses login()');

  @override
  Future<String> accessToken() async {
    // The engine owns the OAuth session on desktop too, so the ApiClient has no
    // token of its own: without this the backend REST calls behind the apps and
    // resources screens would go out with no Authorization header. The agent
    // refreshes transparently and answers 401 when signed out.
    final json = _asMap(await _send('GET', '/token'), '/token');
    final token = json['access_token'];
    if (token is String && token.isNotEmpty) return token;
    throw const EngineException(0, 'engine returned no access token');
  }

  @override
  Future<void> logout() async {
    await _send('POST', '/logout');
  }

  @override
  Future<DeviceState> deviceState() async =>
      DeviceState.fromJson(_asMap(await _send('GET', '/device-state'), '/device-state'));

  @override
  Future<EnrollResult> enroll(String code, {String? serverUrl}) async =>
      EnrollResult.fromJson(_asMap(
          await _send('POST', '/enroll', {
            'code': code,
            if (serverUrl != null && serverUrl.trim().isNotEmpty)
              'server': serverUrl.trim(),
          }),
          '/enroll'));

  @override
  Future<bool> registerPushDevice(String deviceToken, String platform) async {
    // Desktop is not a push-MFA authenticator; nothing to register.
    return false;
  }

  @override
  Future<void> setServer(String url) async {
    // Desktop resolves the server from the installed sidecar config.
  }

  @override
  Future<Posture> posture() async =>
      Posture.fromJson(_asMap(await _send('GET', '/posture'), '/posture'));

  @override
  Future<List<PamEntry>> pamList() async {
    final raw = await _send('GET', '/pam/entries');
    if (raw is! List) {
      throw const EngineException(0, 'unexpected response shape from /pam/entries');
    }
    return raw
        .whereType<Map<String, dynamic>>()
        .map(PamEntry.fromJson)
        .toList(growable: false);
  }

  @override
  Future<PamConnectResult> pamConnect(String entryId) async =>
      PamConnectResult.fromJson(_asMap(
          await _send('POST', '/pam/connect', {'entry_id': entryId}),
          '/pam/connect'));

  @override
  Future<void> pamRequest(String entryId, String reason) async {
    await _send('POST', '/pam/request', {'entry_id': entryId, 'reason': reason});
  }

  @override
  Future<String> zitiDial(String service) async {
    final raw = await _send('POST', '/ziti/dial', {'service': service});
    final map = _asMap(raw, '/ziti/dial');
    final addr = map['addr'] ?? map['url'] ?? map['local_addr'];
    return addr is String ? addr : '';
  }

  @override
  Future<void> zitiClose(String service) async {
    await _send('POST', '/ziti/close', {'service': service});
  }

  @override
  void close() {
    _http?.close(force: true);
    _http = null;
  }
}
