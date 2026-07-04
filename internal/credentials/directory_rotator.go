package credentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/openidx/openidx/internal/directory"
)

type directoryRotator struct{ dir *directory.Service }

// NewDirectoryRotator returns a Rotator that applies credential changes via the
// directory connector (LDAP/AD). Exported so cmd/admin-api can construct the
// rotator slice without importing the unexported type directly.
func NewDirectoryRotator(dir *directory.Service) Rotator { return &directoryRotator{dir: dir} }

func (d *directoryRotator) Type() string { return "directory" }

func (d *directoryRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	dirID, _ := cfg["directory_id"].(string)
	user, _ := cfg["username"].(string)
	if dirID == "" || user == "" {
		return fmt.Errorf("directory connector requires directory_id and username")
	}
	return d.dir.ResetPassword(ctx, dirID, user, string(newValue))
}

func (d *directoryRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	dirID, _ := cfg["directory_id"].(string)
	user, _ := cfg["username"].(string)
	err := d.dir.VerifyPassword(ctx, dirID, user, string(newValue))
	if errors.Is(err, directory.ErrVerifyUnsupported) {
		return ErrVerifyUnsupported
	}
	return err
}

// ValidateConfig satisfies ConfigValidator: requires directory_id and username
// (matches Apply's requirements).
func (d *directoryRotator) ValidateConfig(cfg map[string]any) error {
	dirID, _ := cfg["directory_id"].(string)
	user, _ := cfg["username"].(string)
	if dirID == "" || user == "" {
		return fmt.Errorf("directory connector requires directory_id and username")
	}
	return nil
}
