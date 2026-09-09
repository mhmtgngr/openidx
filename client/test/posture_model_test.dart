import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/engine/models.dart';

/// The posture summary is the one place the app tells a user whether their own
/// device is healthy, so what it does with "I could not check" decides whether
/// that sentence is true.
///
/// Until v1.34.0 the engine answered every check it has no implementation for
/// with a warning, and warnings did not deny compliance. On Android and iOS —
/// the gomobile builds this app is — seven of the ten checks are in that
/// position, disk encryption among them at severity critical. The payload said
/// compliant, and the card drew it in green.
///
/// These cases pin the parsing side of the fix: the engine's new fields must
/// survive into the model, and a payload from an older engine (no field at
/// all) must not be read as "everything was checked".

Posture parse(Map<String, dynamic> json) =>
    Posture.fromJson(jsonDecode(jsonEncode(json)) as Map<String, dynamic>);

void main() {
  test('the unsupported count is carried off the wire', () {
    final p = parse({
      'compliant': false,
      'passed': 1,
      'failed': 0,
      'warned': 0,
      'errored': 0,
      'unsupported': 7,
      'ran_at': '2026-01-01T00:00:00Z',
      'checks': [
        {'type': 'agent_version', 'severity': 'low', 'status': 'pass', 'score': 1},
        {
          'type': 'disk_encryption',
          'severity': 'critical',
          'status': 'warn',
          'score': 0.5,
          'message': 'disk encryption check not supported on android',
          'unsupported': true,
        },
      ],
    });

    expect(p.unsupported, 7);
    expect(p.compliant, isFalse);
    expect(p.assessable, isTrue, reason: 'one check did run');

    final byType = {for (final c in p.checks) c.type: c};
    expect(byType['disk_encryption']!.unsupported, isTrue,
        reason: 'the card needs to know WHICH check could not run, not just how many');
    expect(byType['agent_version']!.unsupported, isFalse);
  });

  test('a device where nothing ran is not assessable', () {
    final p = parse({
      'compliant': false,
      'passed': 0,
      'failed': 0,
      'warned': 0,
      'errored': 0,
      'unsupported': 3,
      'ran_at': '2026-01-01T00:00:00Z',
      'checks': const [],
    });

    expect(p.assessable, isFalse);
    expect(p.compliant, isFalse);
  });

  test('a real result is still assessable and can be compliant', () {
    final p = parse({
      'compliant': true,
      'passed': 3,
      'failed': 0,
      'warned': 1,
      'errored': 0,
      'unsupported': 0,
      'ran_at': '2026-01-01T00:00:00Z',
      'checks': const [],
    });

    expect(p.assessable, isTrue);
    expect(p.compliant, isTrue);
    expect(p.unsupported, 0);
  });

  test('a payload with no unsupported field defaults to zero, not to a guess', () {
    // An older engine binary paired with a newer app. Zero is the right
    // default: it means "this engine did not tell us", and the engine's own
    // compliant flag — which that build computed the old way — is all there is.
    // The app must not invent a count.
    final p = parse({
      'compliant': true,
      'passed': 2,
      'failed': 0,
      'warned': 0,
      'errored': 0,
      'ran_at': '2026-01-01T00:00:00Z',
      'checks': const [],
    });

    expect(p.unsupported, 0);
    expect(p.assessable, isTrue);
  });

  test('the empty posture claims nothing', () {
    expect(Posture.empty.compliant, isFalse);
    expect(Posture.empty.unsupported, 0);
    expect(Posture.empty.assessable, isFalse,
        reason: 'a posture nobody has fetched must not read as a healthy device');
  });
}
