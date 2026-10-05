package control

import "path/filepath"

// endpointFileName holds the loopback address and bearer token a Windows
// engine publishes so the desktop GUI can reach its control server. Only the
// Windows listener writes it. The path rule below is untagged so that every
// runner tests it, not only a Windows one.
const endpointFileName = "control-endpoint.json"

// endpointPathFor chooses where the endpoint file goes, given the values of
// %LOCALAPPDATA%, %ProgramData% and the temp directory.
//
// The user's own LOCALAPPDATA comes first. The engine the GUI talks to runs in
// that user's session and the file carries the bearer for it, so it belongs in
// the user's profile, which other users cannot open (administrators aside). It
// used to go to %ProgramData%, which every account on the machine shares.
// ProgramData stays as the fallback for a process that has no LOCALAPPDATA,
// such as one running as SYSTEM, and the temp directory is the last resort.
func endpointPathFor(localAppData, programData, tempDir string) string {
	base := localAppData
	if base == "" {
		base = programData
	}
	if base == "" {
		base = tempDir
	}
	return filepath.Join(base, "OpenIDX", "agent", endpointFileName)
}
