import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/api/api_client.dart';
import 'package:openidx_client/mobile/push_setup.dart';

/// The server refuses to add a push device to an account that already has a
/// second factor unless the request carries the account password, and says so
/// with 403 and a code. These pin how the app reads that answer, which decides
/// whether it asks the person for their password.
///
/// > Runs in CI via `.github/workflows/client-mobile-build.yml` (`flutter test`).
void main() {
  test('a refusal that wants the password asks for it', () {
    expect(pushSetupOutcomeOf(const ApiException(403, 'reauthentication_required')),
        PushSetupOutcome.needsPassword);
  });
  test('a wrong password and a lockout are told apart', () {
    expect(pushSetupOutcomeOf(const ApiException(403, 'reauthentication_failed')),
        PushSetupOutcome.wrongPassword);
    expect(pushSetupOutcomeOf(const ApiException(403, 'reauthentication_locked')),
        PushSetupOutcome.locked);
  });
  test('anything else is a plain failure', () {
    expect(pushSetupOutcomeOf(const ApiException(403, 'forbidden')), PushSetupOutcome.failed);
    expect(pushSetupOutcomeOf(const ApiException(0, 'request failed')), PushSetupOutcome.failed);
    expect(pushSetupOutcomeOf(StateError('x')), PushSetupOutcome.failed);
  });
}
