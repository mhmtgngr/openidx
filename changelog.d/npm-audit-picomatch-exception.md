### Security
- **The console's npm audit excuses GHSA-fc5q-39xc-vjpf until 2026-12-18.** An advisory
  against picomatch (<= 4.0.7, ReDoS through repeated extglobs) was published on
  2026-11-18 with no patched release (4.0.7 is the latest), and turned the
  dependency scan red on every pull request at once. picomatch reaches the console
  only through vite, vitest and tinyglobby, which are build and test tooling
  (`npm audit --omit=dev` reports no high or critical advisory), and the globs they
  match are this repository's own configuration. The entry names the advisory, not
  the package, so a second advisory against picomatch still fails, and it lapses on
  its date.
