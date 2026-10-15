### Changed
- **The Kotlin Android agent and the Flutter desktop shell are frozen.** Both
  are on hold per ROADMAP.md (#1185). Their CI now runs only on demand (the
  Android build also on changes under `agent-android/`), the Android
  workflow's unit-test job, which had no test sources to run, is gone, and the
  README's maturity matrix marks both "Experimental, on hold" with the
  condition under which each is deleted. Neither was distributed; the Windows
  agent and the Flutter mobile app are unaffected.
- **The Agent Fleet page says when no Android agent APK is published.** The
  Android enrollment QR dialog now asks the server for the APK
  (`GET /api/v1/access/agent/apk-info`) and, where none is published, explains
  that the Android agent is on hold instead of offering a download link that
  answers 404.
