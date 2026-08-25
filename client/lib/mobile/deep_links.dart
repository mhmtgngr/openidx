import 'dart:async';

import 'package:app_links/app_links.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// A parsed inbound deep link the app knows how to route.
sealed class OpenidxDeepLink {
  const OpenidxDeepLink();

  /// Parse a `openidx://…` URI, or null if it isn't one we handle.
  static OpenidxDeepLink? parse(Uri uri) {
    if (uri.scheme != 'openidx') return null;
    switch (uri.host) {
      case 'oauth-callback':
        final code = uri.queryParameters['code'];
        if (code == null || code.isEmpty) return null;
        return OAuthCallbackLink(code: code, raw: uri);
      case 'enroll':
        // openidx://enroll?code=<token>&server=<baseUrl> — issued by the admin
        // console (POST /agent/enroll/session) as a QR / copyable link. The
        // `server` is the half mobile cannot get any other way: the engine
        // starts with no configured server and has no CLI flag to set one.
        final code = uri.queryParameters['code'];
        if (code == null || code.isEmpty) return null;
        return EnrollLink(
          code: code,
          server: uri.queryParameters['server'] ?? '',
        );
      case 'approve':
        // openidx://approve/<challengeId>
        final id = uri.pathSegments.isNotEmpty ? uri.pathSegments.first : '';
        if (id.isEmpty) return null;
        return ApproveLink(challengeId: id);
      default:
        return null;
    }
  }
}

/// `openidx://oauth-callback?code=…` — the browser PKCE fallback redirect.
class OAuthCallbackLink extends OpenidxDeepLink {
  const OAuthCallbackLink({required this.code, required this.raw});
  final String code;
  final Uri raw;
}

/// `openidx://enroll?code=…&server=…` — the admin console's enrollment link.
///
/// [server] may be empty if the console omitted it, in which case the enroll
/// screen keeps whatever the user typed rather than clearing it.
class EnrollLink extends OpenidxDeepLink {
  const EnrollLink({required this.code, required this.server});
  final String code;
  final String server;
}

/// `openidx://approve/<challengeId>` — a push-approval deep link.
class ApproveLink extends OpenidxDeepLink {
  const ApproveLink({required this.challengeId});
  final String challengeId;
}

/// Listens for inbound deep links (cold-start + while running) via `app_links`
/// and exposes them as a stream. The router/UI subscribes and navigates;
/// `AuthService.browserAuthorize` awaits the next [OAuthCallbackLink].
class DeepLinkService {
  DeepLinkService({AppLinks? appLinks}) : _appLinks = appLinks ?? AppLinks();

  final AppLinks _appLinks;
  final _controller = StreamController<OpenidxDeepLink>.broadcast();
  StreamSubscription<Uri>? _sub;
  bool _initialized = false;

  Stream<OpenidxDeepLink> get links => _controller.stream;

  /// Begin listening. Emits the initial (cold-start) link, if any, then all
  /// subsequent ones.
  Future<void> init() async {
    if (_initialized) return;
    _initialized = true;

    final initial = await _appLinks.getInitialLink();
    if (initial != null) _emit(initial);

    _sub = _appLinks.uriLinkStream.listen(_emit);
  }

  /// Convenience for the browser OAuth fallback: resolve with the next
  /// `code` from an [OAuthCallbackLink].
  Future<String> nextOAuthCode() {
    return links
        .where((l) => l is OAuthCallbackLink)
        .cast<OAuthCallbackLink>()
        .map((l) => l.code)
        .first;
  }

  void _emit(Uri uri) {
    final link = OpenidxDeepLink.parse(uri);
    if (link != null) _controller.add(link);
  }

  Future<void> dispose() async {
    await _sub?.cancel();
    await _controller.close();
  }
}

final deepLinkServiceProvider = Provider<DeepLinkService>((ref) {
  final service = DeepLinkService();
  ref.onDispose(service.dispose);
  return service;
});
