// Package config provides tests for configuration management
package config

import (
	"testing"
	"time"
)

func TestShutdownTimeout(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want time.Duration
	}{
		{"zero value defaults to 30s", Config{}, 30 * time.Second},
		{"explicit positive value", Config{ShutdownTimeoutSeconds: 10}, 10 * time.Second},
		{"non-positive guard defaults to 30s", Config{ShutdownTimeoutSeconds: -5}, 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.ShutdownTimeout(); got != tt.want {
				t.Errorf("ShutdownTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}
