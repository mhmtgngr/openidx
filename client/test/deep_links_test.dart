import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/mobile/deep_links.dart';

/// Verifies openidx:// deep-link parsing, focused on the new QR-free
/// `openidx://enroll` link.
///
/// > Runs in CI via `.github/workflows/client-mobile-build.yml` (`flutter test`).
void main() {
  group('OpenidxDeepLink.parse', () {
    test('parses openidx://enroll?code=…&server=…', () {
      final link = OpenidxDeepLink.parse(
          Uri.parse('openidx://enroll?code=abc123&server=https://openidx.tdv.org'));
      expect(link, isA<EnrollLink>());
      final e = link! as EnrollLink;
      expect(e.code, 'abc123');
      expect(e.server, 'https://openidx.tdv.org');
    });

    test('enroll link without server keeps server empty', () {
      final link = OpenidxDeepLink.parse(Uri.parse('openidx://enroll?code=xyz'));
      expect(link, isA<EnrollLink>());
      expect((link! as EnrollLink).server, '');
    });

    test('enroll link without a code is rejected', () {
      expect(OpenidxDeepLink.parse(Uri.parse('openidx://enroll')), isNull);
      expect(OpenidxDeepLink.parse(Uri.parse('openidx://enroll?code=')), isNull);
    });

    test('parses openidx://qr-login?session=…', () {
      final link =
          OpenidxDeepLink.parse(Uri.parse('openidx://qr-login?session=tok123'));
      expect(link, isA<LoginQrLink>());
      expect((link! as LoginQrLink).sessionToken, 'tok123');
    });

    test('qr-login without a session is rejected', () {
      expect(OpenidxDeepLink.parse(Uri.parse('openidx://qr-login')), isNull);
      expect(
          OpenidxDeepLink.parse(Uri.parse('openidx://qr-login?session=')), isNull);
    });

    test('still parses oauth-callback and approve', () {
      expect(
          OpenidxDeepLink.parse(Uri.parse('openidx://oauth-callback?code=c')),
          isA<OAuthCallbackLink>());
      expect(OpenidxDeepLink.parse(Uri.parse('openidx://approve/chal-1')),
          isA<ApproveLink>());
    });

    test('ignores non-openidx schemes', () {
      expect(OpenidxDeepLink.parse(Uri.parse('https://enroll?code=x')), isNull);
    });
  });
}
