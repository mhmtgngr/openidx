package access

import (
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/config"
)

func TestUserSyncKnobs(t *testing.T) {
	zm := &ZitiManager{}
	if zm.userSyncBatch() != 100 || zm.userSyncInterval() != 30*time.Second {
		t.Fatal("defaults")
	}
	zm.cfg = &config.Config{ZitiUserSyncBatch: 250, ZitiUserSyncInterval: 10 * time.Second}
	if zm.userSyncBatch() != 250 || zm.userSyncInterval() != 10*time.Second {
		t.Fatal("configured values")
	}
	zm.cfg = &config.Config{ZitiUserSyncBatch: 99999, ZitiUserSyncInterval: time.Millisecond}
	if zm.userSyncBatch() != 1000 || zm.userSyncInterval() != 5*time.Second {
		t.Fatal("clamps")
	}
}
