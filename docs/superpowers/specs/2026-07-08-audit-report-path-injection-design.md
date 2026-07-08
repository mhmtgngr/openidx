# Audit report export: path-injection fix

**Goal:** `processExport` builds a report file path from request-controlled `report_type`/`format`
without path sanitization, then `os.Create`/`os.Stat` it — CodeQL `go/path-injection` (high ×3,
`internal/audit/reports.go:151/304/336`) and a real traversal: a `report_type`/`format` containing
`../` could write/stat a file outside the report directory.

**Verified current state (`internal/audit/reports.go`):**
- `reportDir = "/tmp/openidx-reports"` (const).
- Line ~131: `fileName := fmt.Sprintf("%s_%s_%s.%s", export.ReportType, export.ID[:8], <ts>, export.Format)`;
  line ~132: `filePath := filepath.Join(reportDir, fileName)`. `ReportType`/`Format` come from the export
  request (`ShouldBindJSON`), unvalidated for path safety before this join.
- `filePath` flows to `os.Stat` (:151) and to `writeCSVFile`/`writeJSONFile` → `os.Create` (:304/:336).

## Design
Constrain the joined name to a single path element via `filepath.Base` (a CodeQL-recognized
path-injection sanitizer) at the construction barrier, so all three downstream sinks receive a
contained path:
```go
// reportFilePath joins a report file name under reportDir, constraining it to a single path
// element (filepath.Base) so a path-traversing report_type/format in the export request cannot
// escape reportDir.
func reportFilePath(fileName string) string {
	return filepath.Join(reportDir, filepath.Base(fileName))
}
```
Caller: `filePath := reportFilePath(fileName)` (replaces the raw `filepath.Join(reportDir, fileName)`).
Normal names (`soc2_abc_20260708.csv`) are unchanged; a malicious `report_type="../../etc/x"` collapses
to its base element under `reportDir`. No behavior change for legitimate exports.

## Testing / verification
- Unit test `TestReportFilePath`: a normal fileName → `reportDir/<name>`; a traversing fileName
  (`../../etc/passwd`, `a/../../b.csv`) → still under `reportDir` (assert `filepath.Dir(result) == reportDir`
  and `strings.HasPrefix(result, reportDir+"/")`).
- `go build ./... && go vet ./internal/audit/ && gofmt -l && go test ./internal/audit/` clean;
  `golangci-lint run ./internal/audit/` clean.
- Post-PR: the 3 `go/path-injection` alerts clear on the merge-ref.

## Scope / risk
- One helper + one call site in `internal/audit/reports.go` + a unit test. No behavior change for valid
  input; a traversing input is neutralized (contained under `reportDir`). No migration.
- Box-relevant (audit-service) but the export path is `/tmp/openidx-reports`; low runtime impact —
  deploy can ride the next release.
- Out of scope (remaining high backlog): `remote_support_recording.go` path-injection ×4 (already
  charset-sanitized → FP dismiss), `go/weak-sensitive-data-hashing` ×5, `js/empty-password-in-configuration-file` ×2.
