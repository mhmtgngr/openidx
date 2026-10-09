package tray

import "strings"

// notifyIconPathMatches reports whether an ExecutablePath value Explorer
// stored under HKCU\Control Panel\NotifyIconSettings names exe.
//
// Explorer writes a path under a known folder as that folder's GUID followed
// by the rest of the path, e.g.
// {6D809377-6AF0-444B-8957-A3773F02200E}\OpenIDX\openidx-agent.exe for
// C:\Program Files\OpenIDX\openidx-agent.exe, and any other path in full.
// knownFolders maps an upper-case "{GUID}" to the folder's path.
func notifyIconPathMatches(stored, exe string, knownFolders map[string]string) bool {
	if strings.HasPrefix(stored, "{") {
		if end := strings.Index(stored, "}"); end > 0 {
			if dir, ok := knownFolders[strings.ToUpper(stored[:end+1])]; ok {
				stored = strings.TrimRight(dir, `\`) + stored[end+1:]
			}
		}
	}
	return strings.EqualFold(stored, exe)
}
