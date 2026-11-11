package updater

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// Update rings (Faz B8.5): the server tells each device which feed to read,
// which version to aim for, and whether it may move at all. The device obeys
// that over the URL compiled into it, which stays the fallback for a server
// that sends nothing.

// Target is the server's update block (/agent/config "update").
type Target struct {
	ManifestURL    string `json:"manifest_url"`
	TargetVersion  string `json:"target_version,omitempty"`
	Channel        string `json:"channel"`
	Paused         bool   `json:"paused"`
	AllowDowngrade bool   `json:"allow_downgrade"`
}

// Result is the outcome of one update check, reported to the server.
type Result struct {
	State   string `json:"state"` // ok | failed | applying | held
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
	At      string `json:"at,omitempty"`
}

// Decision is what a check does with a manifest.
type Decision int

const (
	// Stay: nothing to install.
	Stay Decision = iota
	// Upgrade to the manifest's version.
	Upgrade
	// Downgrade to the manifest's version (a pin below what runs).
	Downgrade
)

// Decide compares the running version with the manifest's under the
// server's target. A pause installs nothing. A pin installs only the pinned
// version: up to it as usual, down to it only when the server allows it.
// Without a pin the device moves forward only.
func Decide(current, manifestVersion string, t *Target) Decision {
	current = strings.TrimPrefix(current, "v")
	manifestVersion = strings.TrimPrefix(manifestVersion, "v")
	if t != nil && t.Paused {
		return Stay
	}
	if t != nil && t.TargetVersion != "" {
		if !sameVersion(manifestVersion, t.TargetVersion) {
			return Stay
		}
		switch {
		case Newer(current, manifestVersion):
			return Upgrade
		case t.AllowDowngrade && current != "dev" && current != "" && Newer(manifestVersion, current):
			return Downgrade
		}
		return Stay
	}
	if Newer(current, manifestVersion) {
		return Upgrade
	}
	return Stay
}

func sameVersion(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

// VersionedManifestURL is the manifest of one release next to a channel's
// latest.json: CI publishes each release's latest.json under its own tag,
// agent-v<version>, so a pin can name an older build. It answers "" for a
// URL that is not a GitHub-style release-download URL.
func VersionedManifestURL(channelURL, version string) string {
	const marker = "/releases/download/"
	i := strings.Index(channelURL, marker)
	if i < 0 || version == "" {
		return ""
	}
	rest := channelURL[i+len(marker):]
	j := strings.Index(rest, "/")
	if j < 0 {
		return ""
	}
	return channelURL[:i+len(marker)] + "agent-v" + strings.TrimPrefix(version, "v") + rest[j:]
}

// FirstCheckDelay is how long a freshly started service waits before its
// first update check: 5 minutes plus up to 10 more, so a fleet that boots at
// 08:00 does not reach the feed in one second.
func FirstCheckDelay(r *rand.Rand) time.Duration {
	return 5*time.Minute + time.Duration(r.Int63n(int64(10*time.Minute)))
}

// NextCheckDelay is the interval between later checks: six hours, give or
// take thirty minutes.
func NextCheckDelay(r *rand.Rand) time.Duration {
	return 6*time.Hour - 30*time.Minute + time.Duration(r.Int63n(int64(time.Hour)))
}

// CheckTarget runs one update check under the server's target, falling back
// to fallbackURL when the server named no feed. It returns the result to
// report; Stay answers state "ok" (or "held" when paused).
func CheckTarget(ctx context.Context, t *Target, fallbackURL, current string, trust Trust) Result {
	now := time.Now().UTC().Format(time.RFC3339)
	url := fallbackURL
	if t != nil && t.ManifestURL != "" {
		url = t.ManifestURL
	}
	if url == "" {
		return Result{State: "ok", Version: current, At: now}
	}
	if t != nil && t.Paused {
		return Result{State: "held", Version: current, At: now}
	}
	m, err := Fetch(ctx, url, trust)
	if err == nil && t != nil && t.TargetVersion != "" && !sameVersion(m.Version, t.TargetVersion) {
		if v := VersionedManifestURL(url, t.TargetVersion); v != "" {
			m, err = Fetch(ctx, v, trust)
		}
	}
	if err != nil {
		return Result{State: "failed", Version: current, Error: err.Error(), At: now}
	}
	d := Decide(current, m.Version, t)
	if d == Stay {
		return Result{State: "ok", Version: current, At: now}
	}
	if err := installManifest(ctx, m, d == Downgrade); err != nil {
		return Result{State: "failed", Version: m.Version, Error: err.Error(), At: now}
	}
	return Result{State: "applying", Version: m.Version, At: now}
}

// installManifest downloads, re-verifies and applies a fetched manifest's
// artifact, keeping the installer as prev.msi for a rollback.
func installManifest(ctx context.Context, m *Manifest, downgrade bool) error {
	dir, err := privateDir()
	if err != nil {
		return err
	}
	path, err := downloadVerified(ctx, dir, m.URL, m.SHA256)
	if err != nil {
		return err
	}
	verifyHook(path)
	if err := verifyFile(path, m.SHA256); err != nil {
		return err
	}
	keepPrevious(dir, path)
	if downgrade {
		err = applyDowngradeFn(path)
	} else {
		err = applyFn(path)
	}
	if err != nil {
		return fmt.Errorf("apply %s: %w", m.Version, err)
	}
	return nil
}

// applyDowngradeFn is applyDowngrade, swapped in tests.
var applyDowngradeFn = applyDowngrade
