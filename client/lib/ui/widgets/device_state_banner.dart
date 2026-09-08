import 'package:flutter/material.dart';

import '../../engine/models.dart';

/// The one surface that tells the user what this device is allowed to do.
///
/// The design's first rule is that a device starts with the minimum and earns
/// more by proving things, and that its user always sees which of those it has.
/// Before this, the client showed "Enrolled: Yes" and nothing else, so a device
/// waiting for an administrator looked exactly like a device that was working,
/// and a revoked one looked like a network problem.
///
/// Each state gets one line of what it means and one line of what changes it.
/// Nothing here spins: an unreachable server says so, because a spinner on a
/// state the user cannot influence is just a lie with an animation.
class DeviceStateBanner extends StatelessWidget {
  const DeviceStateBanner({super.key, required this.state, this.onRefresh});

  final DeviceState state;
  final VoidCallback? onRefresh;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final v = _view(state, scheme);

    return Card(
      color: v.background,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(v.icon, color: v.foreground, semanticLabel: v.title),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    v.title,
                    style: Theme.of(context)
                        .textTheme
                        .titleMedium
                        ?.copyWith(color: v.foreground, fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(height: 4),
                  Text(v.detail, style: TextStyle(color: v.foreground)),
                  if (v.next.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    Text(
                      v.next,
                      style: Theme.of(context)
                          .textTheme
                          .bodySmall
                          ?.copyWith(color: v.foreground),
                    ),
                  ],
                ],
              ),
            ),
            if (onRefresh != null)
              IconButton(
                tooltip: 'Check again',
                icon: Icon(Icons.refresh, color: v.foreground),
                onPressed: onRefresh,
              ),
          ],
        ),
      ),
    );
  }

  static _BannerView _view(DeviceState s, ColorScheme scheme) {
    if (!s.enrolled && s.state == 'not_enrolled') {
      return _BannerView(
        icon: Icons.phonelink_setup,
        title: 'This device is not enrolled',
        detail: 'Enrol it to reach your apps and network resources.',
        next: 'Use the enrolment code or QR from the console.',
        background: scheme.surface,
        foreground: scheme.onSurface,
      );
    }
    switch (s.state) {
      case 'pending':
        return _BannerView(
          icon: Icons.hourglass_top,
          title: 'Waiting for approval',
          detail:
              'This device is enrolled. An administrator has to approve it before it can reach anything.',
          next: 'Nothing to do here — you will be let in once it is approved.',
          background: scheme.tertiaryContainer,
          foreground: scheme.onTertiaryContainer,
        );
      case 'active':
        if (s.deviceTrusted) {
          return _BannerView(
            icon: Icons.verified_user,
            title: 'Trusted device',
            detail:
                'This device has proved it is healthy, so it reaches everything your account is entitled to.',
            next: '',
            background: scheme.primaryContainer,
            foreground: scheme.onPrimaryContainer,
          );
        }
        return _BannerView(
          icon: Icons.check_circle_outline,
          title: 'Enrolled',
          detail:
              'This device reaches your own apps and self-service. It has not yet earned device trust.',
          next: 'Trust follows a healthy posture report, where posture can be measured.',
          background: scheme.secondaryContainer,
          foreground: scheme.onSecondaryContainer,
        );
      case 'suspended':
        return _BannerView(
          icon: Icons.pause_circle_outline,
          title: 'On hold',
          detail: 'An administrator has suspended this device. Access is paused.',
          next: 'Contact your administrator.',
          background: scheme.tertiaryContainer,
          foreground: scheme.onTertiaryContainer,
        );
      case 'revoked':
        return _BannerView(
          icon: Icons.gpp_bad,
          title: 'This device has been revoked',
          detail:
              'An administrator took it off the fleet. Its network access and its sign-in have both ended.',
          next: 'Enrol again from the console if you still need this device.',
          background: scheme.errorContainer,
          foreground: scheme.onErrorContainer,
        );
      default:
        // "unknown": the server could not be asked. Never render this as a
        // refusal — the device may be perfectly fine and simply offline.
        return _BannerView(
          icon: Icons.cloud_off,
          title: 'Cannot check with the server',
          detail: s.serverReachable
              ? 'The server answered but did not say what this device is allowed to do.'
              : 'This device is enrolled. Its current permissions could not be checked just now.',
          next: 'Anything already working keeps working. Try again when you are back online.',
          background: scheme.surface,
          foreground: scheme.onSurface,
        );
    }
  }
}

class _BannerView {
  const _BannerView({
    required this.icon,
    required this.title,
    required this.detail,
    required this.next,
    required this.background,
    required this.foreground,
  });

  final IconData icon;
  final String title;
  final String detail;
  final String next;
  final Color background;
  final Color foreground;
}
