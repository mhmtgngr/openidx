package agent

import "github.com/openidx/openidx/agent/internal/secretfile"

func writeRawConfig(dir string, raw []byte) error {
	return secretfile.WriteShared(ConfigPath(dir), raw)
}
