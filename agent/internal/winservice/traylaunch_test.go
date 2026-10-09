package winservice

import (
	"reflect"
	"testing"
)

func ids(ss []userSession) []uint32 {
	var out []uint32
	for _, s := range ss {
		out = append(out, s.ID)
	}
	return out
}

func TestTraysToLaunch(t *testing.T) {
	cases := []struct {
		name     string
		sessions []userSession
		withTray map[uint32]bool
		launched map[uint32]uint64
		want     []uint32
	}{
		{
			name:     "a signed-in session with no tray gets one",
			sessions: []userSession{{ID: 1, Active: true, Logon: 0x1001}},
			want:     []uint32{1},
		},
		{
			name:     "a session that already has a tray gets none",
			sessions: []userSession{{ID: 1, Active: true, Logon: 0x1001}},
			withTray: map[uint32]bool{1: true},
		},
		{
			name:     "a tray the person quit is not brought back in the same logon",
			sessions: []userSession{{ID: 1, Active: true, Logon: 0x1001}},
			launched: map[uint32]uint64{1: 0x1001},
		},
		{
			name:     "a new sign-in in a reused session id gets a tray",
			sessions: []userSession{{ID: 1, Active: true, Logon: 0x2002}},
			launched: map[uint32]uint64{1: 0x1001},
			want:     []uint32{1},
		},
		{
			name: "session 0, disconnected sessions and sessions with nobody signed in are skipped",
			sessions: []userSession{
				{ID: 0, Active: true, Logon: 0x3e7},
				{ID: 2, Active: false, Logon: 0x1001},
				{ID: 3, Active: true, Logon: 0},
				{ID: 4, Active: true, Logon: 0x4004},
			},
			want: []uint32{4},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ids(traysToLaunch(c.sessions, c.withTray, c.launched))
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestForgetEndedSessions(t *testing.T) {
	launched := map[uint32]uint64{1: 0x1001, 2: 0x2002}
	forgetEndedSessions(launched, []userSession{{ID: 1, Active: true, Logon: 0x1001}})
	if _, ok := launched[2]; ok {
		t.Error("the record for ended session 2 was kept")
	}
	if launched[1] != 0x1001 {
		t.Error("the record for live session 1 was dropped")
	}
}
