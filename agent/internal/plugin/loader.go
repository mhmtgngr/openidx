package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"go.uber.org/zap"
)

type Loader struct {
	pluginDir string
	logger    *zap.Logger
}

func NewLoader(pluginDir string, logger *zap.Logger) *Loader {
	return &Loader{pluginDir: pluginDir, logger: logger}
}

// Discover scans the plugin directory for valid plugins.
func (l *Loader) Discover() ([]*PluginCheck, error) {
	entries, err := os.ReadDir(l.pluginDir)
	if err != nil {
		if os.IsNotExist(err) {
			l.logger.Debug("Plugin directory not found", zap.String("dir", l.pluginDir))
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin dir: %w", err)
	}

	var plugins []*PluginCheck
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pluginPath := filepath.Join(l.pluginDir, entry.Name())
		manifest, err := LoadManifest(pluginPath)
		if err != nil {
			l.logger.Warn("Skipping plugin: invalid manifest",
				zap.String("dir", entry.Name()), zap.Error(err))
			continue
		}

		// Check platform compatibility
		if !isPlatformSupported(manifest.Platforms) {
			l.logger.Debug("Skipping plugin: unsupported platform",
				zap.String("plugin", manifest.Name),
				zap.String("platform", runtime.GOOS))
			continue
		}

		// Find executable (same name as directory, or manifest.Name)
		execPath := findExecutable(pluginPath, entry.Name(), manifest.Name)
		if execPath == "" {
			l.logger.Warn("Skipping plugin: no executable found",
				zap.String("plugin", manifest.Name))
			continue
		}

		// Create a PluginCheck for each check type
		for _, checkType := range manifest.CheckTypes {
			plugins = append(plugins, NewPluginCheck(manifest, execPath, checkType))
		}

		l.logger.Info("Plugin discovered",
			zap.String("plugin", manifest.Name),
			zap.Int("check_types", len(manifest.CheckTypes)))
	}

	return plugins, nil
}

func isPlatformSupported(platforms []string) bool {
	if len(platforms) == 0 {
		return true // no platform restriction
	}
	for _, p := range platforms {
		if p == runtime.GOOS || p == "all" {
			return true
		}
	}
	return false
}

func findExecutable(dir, dirName, manifestName string) string {
	candidates := []string{
		filepath.Join(dir, dirName),
		filepath.Join(dir, manifestName),
		filepath.Join(dir, dirName+".sh"),
		filepath.Join(dir, manifestName+".sh"),
	}
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			return path
		}
	}
	return ""
}
