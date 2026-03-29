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

func LoadManifest(dir string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
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
