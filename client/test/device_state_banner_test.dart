import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/engine/models.dart';
import 'package:openidx_client/ui/widgets/device_state_banner.dart';

/// The banner is the only place a user is told what this device may do, so
/// every state has to reach the screen in words, and two of them must never be
/// confused with each other: "an administrator has not approved you yet" and
/// "something went wrong".

Future<void> _pump(WidgetTester tester, DeviceState state) async {
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(body: DeviceStateBanner(state: state)),
  ));
}

void main() {
  testWidgets('waiting for approval says so, and says there is nothing to do',
      (tester) async {
    await _pump(
      tester,
      const DeviceState(
        enrolled: true,
        state: 'pending',
        deviceTrusted: false,
        serverReachable: true,
      ),
    );

    expect(find.text('Waiting for approval'), findsOneWidget);
    expect(find.textContaining('administrator has to approve'), findsOneWidget);
    expect(find.textContaining('Nothing to do here'), findsOneWidget);
  });

  testWidgets('enrolled without trust is Tier 1, and says what earns more',
      (tester) async {
    await _pump(
      tester,
      const DeviceState(
        enrolled: true,
        state: 'active',
        deviceTrusted: false,
        serverReachable: true,
      ),
    );

    expect(find.text('Enrolled'), findsOneWidget);
    expect(find.textContaining('has not yet earned device trust'), findsOneWidget);
  });

  testWidgets('a trusted device says so', (tester) async {
    await _pump(
      tester,
      const DeviceState(
        enrolled: true,
        state: 'active',
        deviceTrusted: true,
        serverReachable: true,
      ),
    );

    expect(find.text('Trusted device'), findsOneWidget);
  });

  testWidgets('a revoked device is named, not hidden behind an error',
      (tester) async {
    await _pump(
      tester,
      const DeviceState(
        enrolled: true,
        state: 'revoked',
        deviceTrusted: false,
        serverReachable: true,
      ),
    );

    expect(find.text('This device has been revoked'), findsOneWidget);
    expect(find.textContaining('sign-in have both ended'), findsOneWidget);
  });

  testWidgets('an unreachable server is not rendered as a refusal',
      (tester) async {
    await _pump(
      tester,
      const DeviceState(
        enrolled: true,
        state: 'unknown',
        deviceTrusted: false,
        serverReachable: false,
        error: 'dial tcp: connection refused',
      ),
    );

    expect(find.text('Cannot check with the server'), findsOneWidget);
    expect(find.textContaining('keeps working'), findsOneWidget);
    // The words that would be wrong here.
    expect(find.textContaining('revoked'), findsNothing);
    expect(find.textContaining('approve'), findsNothing);
  });

  testWidgets('a device with no enrolment is told how to get one',
      (tester) async {
    await _pump(tester, DeviceState.unknown.copyForNotEnrolled());

    expect(find.text('This device is not enrolled'), findsOneWidget);
    expect(find.textContaining('enrolment code or QR'), findsOneWidget);
  });

  testWidgets('the refresh action is offered only when a caller handles it',
      (tester) async {
    var refreshed = 0;
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: DeviceStateBanner(
          state: const DeviceState(
            enrolled: true,
            state: 'pending',
            deviceTrusted: false,
            serverReachable: true,
          ),
          onRefresh: () => refreshed++,
        ),
      ),
    ));

    await tester.tap(find.byIcon(Icons.refresh));
    expect(refreshed, 1);
  });
}

extension on DeviceState {
  /// The not-enrolled shape, which the engine reports before any enrolment.
  DeviceState copyForNotEnrolled() => const DeviceState(
        enrolled: false,
        state: 'not_enrolled',
        deviceTrusted: false,
        serverReachable: true,
      );
}
