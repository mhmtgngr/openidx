package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Manifest struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Description    string   `json:"description"`
	Platforms      []string `json:"platforms"`
	CheckTypes     []string `json:"check_types"`
	Schedule       string   `json:"schedule,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

// manifestFileName is the file in each plugin folder that names the plugin and
// the check types it provides.
const manifestFileName = "manifest.json"

func LoadManifest(dir string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifestFileName))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return parseManifest(data)
}

// parseManifest parses manifest.json from bytes already read, so that the
// loader can hash and parse the same bytes. Reading the file a second time to
// parse it would let the manifest that is obeyed differ from the one whose
// digest the signature covers.
func parseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Name == "" {
		return nil, fmt.Errorf("manifest missing required field: name")
	}
	if len(m.CheckTypes) == 0 {
		return nil, fmt.Errorf("manifest missing required field: check_types")
	}
	if m.TimeoutSeconds <= 0 {
		m.TimeoutSeconds = 30
	}
	return &m, nil
}
