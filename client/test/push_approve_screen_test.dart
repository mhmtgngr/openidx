import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/api/api_client.dart';
import 'package:openidx_client/api/mfa.dart';
import 'package:openidx_client/api/token_store.dart';
import 'package:openidx_client/state/api_providers.dart';
import 'package:openidx_client/ui/screens/mobile/push_approve_screen.dart';

/// The approve screen is where a person turns a push prompt into a session for
/// whoever is at the sign-in screen, so it must send the number they type and
/// nothing else, and must say plainly why the server refused an answer.

class _EmptyTokens implements TokenStore {
  @override
  Future<String?> accessToken() async => null;
  @override
  Future<String?> refreshToken() async => null;
  @override
  Future<String?> orgSlug() async => null;
  @override
  Future<void> save({String? access, String? refresh, String? orgSlug}) async {}
  @override
  Future<void> clear() async {}
}

/// Serves one challenge and records every answer, failing the next answer
/// with [failNext] when it is set.
class _FakeMfa extends MfaApi {
  _FakeMfa()
      : super(ApiClient(baseUrl: 'http://localhost', tokens: _EmptyTokens()));

  final answers = <(PushDecision, String?)>[];
  Object? failNext;

  @override
  Future<PushChallenge> pushChallenge(String id) async => PushChallenge(
        id: id,
        appName: 'Admin Console',
        location: 'Berlin, Germany',
        ipAddress: '203.0.113.7',
        browser: 'Firefox',
        requestedAt: '2026-10-05T09:15:30Z',
      );

  @override
  Future<void> pushVerify({
    required String challengeId,
    required PushDecision decision,
    String? challengeCode,
  }) async {
    answers.add((decision, challengeCode));
    final failure = failNext;
    failNext = null;
    if (failure != null) throw failure;
  }
}

Future<_FakeMfa> _open(WidgetTester tester) async {
  final mfa = _FakeMfa();
  await tester.pumpWidget(ProviderScope(
    overrides: [mfaApiProvider.overrideWithValue(mfa)],
    child: const MaterialApp(home: PushApproveScreen(challengeId: 'chal-1')),
  ));
  await tester.pumpAndSettle();
  return mfa;
}

ButtonStyleButton _button(WidgetTester tester, String label) =>
    tester.widget<ButtonStyleButton>(find.ancestor(
      of: find.text(label),
      matching: find.byWidgetPredicate((w) => w is ButtonStyleButton),
    ));

String _typed(WidgetTester tester) =>
    tester.widget<TextField>(find.byType(TextField)).controller!.text;

Future<void> _type(WidgetTester tester, String text) async {
  await tester.enterText(find.byType(TextField), text);
  await tester.pump();
}

Future<void> _tap(WidgetTester tester, String label) async {
  await tester.tap(find.text(label));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('shows what is asking to sign in', (tester) async {
    await _open(tester);

    expect(find.text('Admin Console'), findsOneWidget);
    expect(find.text('Berlin, Germany'), findsOneWidget);
    expect(find.text('203.0.113.7'), findsOneWidget);
    expect(find.text('Firefox'), findsOneWidget);
  });

  testWidgets('Approve stays off until exactly two digits are typed',
      (tester) async {
    final mfa = await _open(tester);

    expect(_button(tester, 'Approve').enabled, isFalse);

    await _type(tester, '4');
    expect(_button(tester, 'Approve').enabled, isFalse);

    // Only digits are kept, and no more than two of them.
    await _type(tester, '4a');
    expect(_typed(tester), '4');
    await _type(tester, '123');
    expect(_typed(tester), '12');

    await _type(tester, '42');
    expect(_button(tester, 'Approve').enabled, isTrue);
    await _tap(tester, 'Approve');

    expect(mfa.answers, [(PushDecision.approve, '42')]);
    expect(find.text('Approved'), findsOneWidget);
  });

  testWidgets('nothing is sent while the number is incomplete', (tester) async {
    final mfa = await _open(tester);

    await _type(tester, '4');
    await tester.tap(find.text('Approve'));
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();

    expect(mfa.answers, isEmpty);
  });

  testWidgets('a wrong number is explained and can be typed again',
      (tester) async {
    final mfa = await _open(tester);
    mfa.failNext = const ApiException(400, 'invalid challenge code');

    await _type(tester, '17');
    await _tap(tester, 'Approve');

    expect(find.textContaining('does not match'), findsOneWidget);
    expect(find.text('Approved'), findsNothing);
    expect(_typed(tester), isEmpty);
    expect(_button(tester, 'Approve').enabled, isFalse);

    await _type(tester, '42');
    await _tap(tester, 'Approve');

    expect(mfa.answers, [
      (PushDecision.approve, '17'),
      (PushDecision.approve, '42'),
    ]);
    expect(find.text('Approved'), findsOneWidget);
  });

  testWidgets('too many wrong numbers closes the request', (tester) async {
    final mfa = await _open(tester);
    mfa.failNext = const ApiException(400,
        'invalid challenge code: too many attempts, this request was denied');

    await _type(tester, '17');
    await _tap(tester, 'Approve');

    expect(find.textContaining('Too many wrong numbers'), findsOneWidget);
    expect(_button(tester, 'Approve').enabled, isFalse);
    expect(_button(tester, 'Deny').enabled, isFalse);
  });

  testWidgets('a device that may not approve is told so, and can still deny',
      (tester) async {
    final mfa = await _open(tester);
    mfa.failNext = const ApiException(403,
        'this device may no longer approve sign-ins: the enrolled device has been revoked');

    await _type(tester, '42');
    await _tap(tester, 'Approve');

    expect(find.textContaining('cannot be approved from this device'),
        findsOneWidget);
    expect(_button(tester, 'Approve').enabled, isFalse);
    expect(_button(tester, 'Deny').enabled, isTrue);
  });

  testWidgets('an expired or answered request is said to be over',
      (tester) async {
    final mfa = await _open(tester);
    mfa.failNext = const ApiException(400, 'challenge expired');

    await _type(tester, '42');
    await _tap(tester, 'Approve');

    expect(
        find.textContaining('expired or was already answered'), findsOneWidget);
    expect(_button(tester, 'Approve').enabled, isFalse);
    expect(_button(tester, 'Deny').enabled, isFalse);
  });

  testWidgets('deny sends no number', (tester) async {
    final mfa = await _open(tester);

    await _tap(tester, 'Deny');

    expect(mfa.answers, [(PushDecision.deny, null)]);
    expect(find.text('Denied'), findsOneWidget);
  });

  testWidgets('report sends no number, even with one typed', (tester) async {
    final mfa = await _open(tester);

    await _type(tester, '42');
    await _tap(tester, 'It wasn’t me — Report');

    expect(mfa.answers, [(PushDecision.report, null)]);
    expect(find.text('Reported'), findsOneWidget);
  });
}
