package winservice

// userSession is one Windows session the service may bring a tray to.
type userSession struct {
	ID     uint32
	Active bool   // WTSActive: someone is signed in and at the screen (console or RDP)
	Logon  uint64 // the signed-in user's logon session id; a new sign-in changes it
}

// traysToLaunch picks the sessions the service should start a tray in.
//
// A tray belongs in every session someone is signed in to. The MSI's Run key
// starts one at sign-in, but nothing started one after an install or an
// upgrade, so a person who had just installed OpenIDX saw nothing until they
// signed out and back in. The service runs as SYSTEM and sees every session,
// so it fills the gap.
//
// It launches at most once per logon. A person can quit the tray, or turn
// "Start when I sign in" off (the launched tray then exits at once), and a
// service that relaunched whenever no tray was running would override both
// every few seconds. Session 0 is the services' own session and has no
// desktop; a disconnected session has nobody to see a tray.
//
// launched maps a session to the logon the service last started a tray for.
// The caller records the returned sessions in it and drops sessions that are
// gone, so a session id Windows reuses for a later sign-in is launched again.
func traysToLaunch(sessions []userSession, withTray map[uint32]bool, launched map[uint32]uint64) []userSession {
	var out []userSession
	for _, s := range sessions {
		if s.ID == 0 || !s.Active || s.Logon == 0 {
			continue
		}
		if withTray[s.ID] {
			continue
		}
		if logon, ok := launched[s.ID]; ok && logon == s.Logon {
			continue
		}
		out = append(out, s)
	}
	return out
}

// forgetEndedSessions drops launch records for sessions that no longer
// exist, so the map does not grow with every sign-in over the service's life.
func forgetEndedSessions(launched map[uint32]uint64, sessions []userSession) {
	live := make(map[uint32]bool, len(sessions))
	for _, s := range sessions {
		live[s.ID] = true
	}
	for id := range launched {
		if !live[id] {
			delete(launched, id)
		}
	}
}
