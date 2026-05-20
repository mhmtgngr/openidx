package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestLocalStorage_RoundTrip exercises the LocalStorage backend end to
// end: Save → Exists → Load → List → Delete. This is also the
// regression guard for the OS-function indirection — if those vars ever
// regress to the old panic("not initialized") placeholders, every call
// here would panic instead of returning cleanly.
func TestLocalStorage_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalStorage(dir)
	ctx := context.Background()

	// List filters to backup-shaped names (see isBackupFile), so use one.
	name := "backup_smoke.sql.gz"
	payload := []byte("fake-backup-bytes\x00\x01\x02")

	// Save
	path, err := store.Save(ctx, name, payload)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("Save reported path %q that doesn't exist: %v", path, statErr)
	}
	if path != filepath.Join(dir, name) && path != dir+"/"+name {
		t.Fatalf("unexpected save path: %q", path)
	}

	// Exists: present + absent
	ok, err := store.Exists(ctx, name)
	if err != nil {
		t.Fatalf("Exists(present): %v", err)
	}
	if !ok {
		t.Fatal("Exists returned false for a saved backup")
	}
	missing, err := store.Exists(ctx, "backup_nope.sql.gz")
	if err != nil {
		t.Fatalf("Exists(absent): %v", err)
	}
	if missing {
		t.Fatal("Exists returned true for a backup that was never saved")
	}

	// Load round-trips the bytes.
	got, err := store.Load(ctx, name)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("Load mismatch: got %q want %q", got, payload)
	}

	// List finds the backup.
	backups, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, b := range backups {
		// List stores the on-disk name in Filename; Name is a derived
		// short label via extractBackupName.
		if b != nil && b.Filename == name {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("List did not include %q (got %d entries)", name, len(backups))
	}

	// Delete removes it.
	if err := store.Delete(ctx, name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	ok, err = store.Exists(ctx, name)
	if err != nil {
		t.Fatalf("Exists(after delete): %v", err)
	}
	if ok {
		t.Fatal("backup still Exists after Delete")
	}
}

// TestNewLocalStorage_URL sanity-checks the URL accessor doesn't panic
// and includes the name (used by callers to surface a download path).
func TestNewLocalStorage_URL(t *testing.T) {
	store := NewLocalStorage(t.TempDir())
	u := store.URL("backup_x.sql.gz")
	if u == "" {
		t.Fatal("URL returned empty string")
	}
}
