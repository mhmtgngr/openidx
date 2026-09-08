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
//
// Every path this returns has passed requireTrustedPath: the root, the plugin's
// own directory and the executable. The callers of LoadPlugins are daemons — one
// of them the Windows service, running as SYSTEM — and what comes back from here
// is handed to exec.CommandContext, so "who else can write this" is the question
// that has to be answered before the answer matters.
func (l *Loader) Discover() ([]*PluginCheck, error) {
	entries, err := os.ReadDir(l.pluginDir)
	if err != nil {
		if os.IsNotExist(err) {
			l.logger.Debug("Plugin directory not found", zap.String("dir", l.pluginDir))
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin dir: %w", err)
	}
	// The root first: a writable root lets anything be added, so no per-plugin
	// check below could stand on its own. An error here refuses the whole
	// directory rather than skipping one entry.
	if err := requireTrustedPath(l.pluginDir); err != nil {
		return nil, fmt.Errorf("plugin directory rejected: %w", err)
	}

	var plugins []*PluginCheck
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pluginPath := filepath.Join(l.pluginDir, entry.Name())
		if err := requireTrustedPath(pluginPath); err != nil {
			l.logger.Warn("Skipping plugin: directory is not safe to execute from",
				zap.String("dir", entry.Name()), zap.Error(err))
			continue
		}
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
		// And the file itself. A tight directory with a world-writable binary
		// inside it is the same hole one level down.
		if err := requireTrustedPath(execPath); err != nil {
			l.logger.Warn("Skipping plugin: executable is not safe to run",
				zap.String("plugin", manifest.Name), zap.Error(err))
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
