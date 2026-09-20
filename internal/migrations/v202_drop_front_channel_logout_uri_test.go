package migrations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The column is dropped because nothing reads or writes it. That premise is
// what this test measures, so the drop cannot outlive a reader that is added
// later without the migration being reconsidered: every non-test Go file
// outside this package must be free of the column's name.
func TestV202DropsAColumnNothingReads(t *testing.T) {
	require.Contains(t, frontChannelLogoutColumnDropUp, "ALTER TABLE oauth_clients DROP COLUMN IF EXISTS front_channel_logout_uri")
	require.Contains(t, frontChannelLogoutColumnDropDown, "ADD COLUMN IF NOT EXISTS front_channel_logout_uri VARCHAR(500)",
		"Down restores the column exactly as v63 declared it")

	root := filepath.Join("..", "..")
	var readers []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasPrefix(rel, filepath.Join("internal", "migrations")) {
			return nil // the migrations that add and drop it are the only legitimate mentions
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "front_channel_logout_uri") || strings.Contains(string(src), "FrontChannelLogoutURI") {
			readers = append(readers, rel)
		}
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, readers, "v202 drops front_channel_logout_uri on the premise that nothing reads it; these files now mention it. If Front-Channel Logout is being added, add the column back in a new migration with the reader, not by reverting v202")
}
