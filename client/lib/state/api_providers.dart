import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../api/access.dart';
import '../api/api_client.dart';
import '../api/governance.dart';
import '../api/mfa.dart';
import '../api/notifications.dart';
import '../api/portal.dart';
import '../api/qr_login.dart';
import '../api/token_store.dart';
import '../features/totp.dart';
import 'providers.dart';

/// Riverpod wiring for the backend HTTP journeys (apps, resources, MFA,
/// governance, notifications, authenticator), shared by mobile AND desktop.
/// These sit alongside the engine providers in `providers.dart`: the engine
/// handles enroll/PAM/Ziti and owns the OAuth session, while these talk HTTP to
/// the backend using a token sourced from it — on desktop too, since the engine
/// gained GET /token.

/// Secure keystore for tokens + otpauth secrets.
final tokenStoreProvider = Provider<TokenStore>((ref) => SecureTokenStore());

final secureStorageProvider = Provider<FlutterSecureStorage>(
  (ref) => const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  ),
);

/// Base URL for the backend gateway. Derived from live agent status
/// (`server_url`) once enrolled; empty until then.
final backendBaseUrlProvider = Provider<String>((ref) {
  return ref.watch(currentStatusProvider).serverUrl;
});

final apiClientProvider = Provider<ApiClient>((ref) {
  // The user signs in through the engine (deep-link OAuth), so the session lives
  // in the engine's store — this client's own TokenStore is empty. Source the
  // Bearer token from the engine so the backend REST journeys authenticate
  // against the SAME session (previously every call 401'd with "missing
  // authorization header"). The engine refreshes the token transparently.
  final engine = ref.watch(engineClientProvider);
  final client = ApiClient(
    baseUrl: ref.watch(backendBaseUrlProvider),
    tokens: ref.watch(tokenStoreProvider),
    engineTokenGetter: engine.accessToken,
  );
  ref.onDispose(() {});
  return client;
});

final mfaApiProvider =
    Provider<MfaApi>((ref) => MfaApi(ref.watch(apiClientProvider)));

final qrLoginApiProvider =
    Provider<QrLoginApi>((ref) => QrLoginApi(ref.watch(apiClientProvider)));

final governanceApiProvider =
    Provider<GovernanceApi>((ref) => GovernanceApi(ref.watch(apiClientProvider)));

final accessApiProvider =
    Provider<AccessApi>((ref) => AccessApi(ref.watch(apiClientProvider)));

final portalApiProvider =
    Provider<PortalApi>((ref) => PortalApi(ref.watch(apiClientProvider)));

final notificationsApiProvider = Provider<NotificationsApi>(
    (ref) => NotificationsApi(ref.watch(apiClientProvider)));

// -- Governance / notifications async providers -------------------------------

final myApprovalsProvider = FutureProvider<List<ApprovalItem>>((ref) {
  return ref.watch(governanceApiProvider).myApprovals();
});

final myRequestsProvider = FutureProvider<List<AccessRequest>>((ref) {
  return ref.watch(governanceApiProvider).myRequests();
});

/// The zero-trust (OpenZiti) apps the signed-in user can reach over the network.
final myZitiServicesProvider = FutureProvider<List<ZitiService>>((ref) {
  return ref.watch(accessApiProvider).myZitiServices();
});

/// Published web apps and brokered (PAM) systems the user can reach.
final myResourcesProvider = FutureProvider<List<MyResource>>((ref) {
  return ref.watch(accessApiProvider).myResources();
});

/// Sign-in (SSO) applications assigned to the user.
final myApplicationsProvider = FutureProvider<List<PortalApp>>((ref) {
  return ref.watch(portalApiProvider).myApplications();
});

final notificationsProvider = FutureProvider<List<AppNotification>>((ref) {
  return ref.watch(notificationsApiProvider).list();
});

// -- Authenticator (offline TOTP) --------------------------------------------

const _totpStorageKey = 'openidx.totp.accounts';

/// Persists + exposes the offline TOTP accounts. Secrets live in the platform
/// keystore; codes are generated on-device (see `features/totp.dart`).
class AuthenticatorController extends StateNotifier<List<OtpAccount>> {
  AuthenticatorController(this._storage) : super(const []) {
    _load();
  }

  final FlutterSecureStorage _storage;

  Future<void> _load() async {
    final raw = await _storage.read(key: _totpStorageKey);
    if (raw != null && raw.isNotEmpty) {
      state = OtpAccount.decodeList(raw);
    }
  }

  Future<void> _persist() =>
      _storage.write(key: _totpStorageKey, value: OtpAccount.encodeList(state));

  /// Add an account from a pasted/scanned `otpauth://` URI.
  Future<void> addFromUri(String uri) async {
    final account = OtpAccount.parseUri(uri);
    state = [
      ...state.where((a) => a.id != account.id),
      account,
    ];
    await _persist();
  }

  Future<void> remove(String id) async {
    state = state.where((a) => a.id != id).toList();
    await _persist();
  }
}

final authenticatorProvider =
    StateNotifierProvider<AuthenticatorController, List<OtpAccount>>((ref) {
  return AuthenticatorController(ref.watch(secureStorageProvider));
});
