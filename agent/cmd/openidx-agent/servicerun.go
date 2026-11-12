package main

import (
	"strings"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/winservice"
)

// serviceRunArgs reports whether args (os.Args[1:]) are the SCM's
// `service run [--config-dir DIR]` command line, and the config dir it names.
// main uses it to hand the process to the service dispatcher before cobra,
// flag defaults or anything that reads agent.json, the registry or the network.
func serviceRunArgs(args []string) (dir string, ok bool) {
	if len(args) < 2 || args[0] != "service" || args[1] != "run" {
		return "", false
	}
	dir = defaultConfigDir()
	rest := args[2:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--config-dir" && i+1 < len(rest):
			dir = rest[i+1]
			i++
		case strings.HasPrefix(a, "--config-dir="):
			dir = strings.TrimPrefix(a, "--config-dir=")
		}
	}
	return dir, true
}

// runServiceFast connects to the SCM first. All config, enrolment and network
// work happens in the service handler after it has reported Running.
func runServiceFast(dir string) error {
	pc := zap.NewProductionConfig()
	logLevel = pc.Level // applyConfigLogLevel adjusts it once Running
	l, err := pc.Build()
	if err != nil {
		l = zap.NewNop()
	}
	logger = l
	configDir = dir
	defer func() { _ = l.Sync() }()
	return winservice.Run(l, dir, Version, applyConfigLogLevel)
}
