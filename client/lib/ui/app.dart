import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../mobile/oauth_login_handler.dart';
import '../state/providers.dart';
import 'mobile_shell.dart';
import 'screens/home_screen.dart';
import 'screens/login_screen.dart';
import 'screens/welcome_screen.dart';

/// Root widget. Chooses the initial screen from live agent status:
///   signed in                    → shell / HomeScreen (works with or without
///                                   device enrollment — authenticator-only is
///                                   a valid state)
///   enrolled, not signed in      → LoginScreen
///   neither                      → WelcomeScreen (sign in as authenticator, or
///                                   enroll a device with a code)
class OpenIdxApp extends ConsumerWidget {
  const OpenIdxApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // On mobile, an app-level handler owns OAuth-callback login completion so it
    // works even when Android cold-starts the app to deliver the redirect (the
    // login screen that was awaiting the callback is gone by then). Mounting it
    // above the router means it lives for the whole app session, independent of
    // which screen is shown. Desktop uses the loopback flow and is unaffected.
    const router = _RootRouter();
    final home = (Platform.isAndroid || Platform.isIOS)
        ? const MobileOAuthLoginHandler(child: router)
        : router;
    return MaterialApp(
      title: 'OpenIDX',
      debugShowCheckedModeBanner: false,
      theme: _lightTheme,
      darkTheme: _darkTheme,
      themeMode: ThemeMode.system,
      home: home,
    );
  }
}

class _RootRouter extends ConsumerWidget {
  const _RootRouter();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final statusAsync = ref.watch(statusProvider);

    return statusAsync.when(
      loading: () => const _Splash(),
      error: (err, _) => _EngineError(message: err.toString()),
      data: (status) {
        // Signed in → straight to the app, whether or not the device is enrolled
        // (authenticator-only sign-in is a first-class flow).
        if (status.loggedIn) {
          if (Platform.isIOS || Platform.isAndroid) return const MobileShell();
          return const HomeScreen();
        }
        // Enrolled but not signed in → the plain sign-in screen (server known).
        if (status.enrolled) return const LoginScreen();
        // Fresh: choose "sign in as authenticator" or "enroll with a code".
        return const WelcomeScreen();
      },
    );
  }
}

class _Splash extends StatelessWidget {
  const _Splash();

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            SizedBox(
              width: 36,
              height: 36,
              child: CircularProgressIndicator(),
            ),
            SizedBox(height: 16),
            Text('Connecting to OpenIDX agent…'),
          ],
        ),
      ),
    );
  }
}

class _EngineError extends ConsumerWidget {
  const _EngineError({required this.message});

  final String message;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.cloud_off, size: 48),
              const SizedBox(height: 12),
              const Text(
                'Cannot reach the OpenIDX agent',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 8),
              Text(
                message,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 13),
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: () => ref.invalidate(statusProvider),
                icon: const Icon(Icons.refresh),
                label: const Text('Retry'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

const _seed = Color(0xFF2F6FED);

final ThemeData _lightTheme = ThemeData(
  useMaterial3: true,
  colorScheme: ColorScheme.fromSeed(seedColor: _seed),
);

final ThemeData _darkTheme = ThemeData(
  useMaterial3: true,
  colorScheme: ColorScheme.fromSeed(
    seedColor: _seed,
    brightness: Brightness.dark,
  ),
);
