### Fixed
- **The tenant-isolation CI job no longer times out on a slow runner.** Its ten
  minute ceiling was shorter than the sum of the suites it runs in series on a
  slow runner, so healthy runs were cancelled at 10m05s (the "DSN role bypasses
  RLS" lines in such a log are the negative control passing, not the failure).
  The ceiling is twenty minutes.
