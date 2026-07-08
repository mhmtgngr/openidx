package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestReportFilePath verifies that reportFilePath constrains the result to reportDir even when the
// file name (built from request-controlled report_type/format) contains path-traversal sequences.
func TestReportFilePath(t *testing.T) {
	cases := []struct {
		name     string
		fileName string
	}{
		{"normal", "soc2_abcdef12_20260708120000.csv"},
		{"leading traversal", "../../etc/passwd"},
		{"embedded traversal", "a/../../b_abcdef12_20260708120000.csv"},
		{"absolute", "/etc/shadow"},
		{"report_type traversal", "../../../tmp/evil_abcdef12_20260708120000.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := reportFilePath(tc.fileName)
			if err != nil {
				t.Fatalf("reportFilePath(%q) unexpected error: %v", tc.fileName, err)
			}
			// Must resolve to a direct child of reportDir — no escape.
			if dir := filepath.Dir(got); dir != reportDir {
				t.Errorf("reportFilePath(%q) = %q; parent dir %q != %q (escaped reportDir)", tc.fileName, got, dir, reportDir)
			}
			if !strings.HasPrefix(got, reportDir+string(filepath.Separator)) {
				t.Errorf("reportFilePath(%q) = %q; not under %q", tc.fileName, got, reportDir)
			}
		})
	}
}
