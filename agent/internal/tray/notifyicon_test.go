package tray

import "testing"

func TestNotifyIconPathMatches(t *testing.T) {
	folders := map[string]string{
		"{6D809377-6AF0-444B-8957-A3773F02200E}": `C:\Program Files`,
	}
	cases := []struct {
		stored, exe string
		want        bool
	}{
		{`{6D809377-6AF0-444B-8957-A3773F02200E}\OpenIDX\openidx-agent.exe`, `C:\Program Files\OpenIDX\openidx-agent.exe`, true},
		{`{6d809377-6af0-444b-8957-a3773f02200e}\OpenIDX\openidx-agent.exe`, `C:\Program Files\OpenIDX\openidx-agent.exe`, true},
		{`D:\openidx-test\app\openidx-agent.exe`, `D:\openidx-test\app\openidx-agent.exe`, true},
		{`d:\OPENIDX-TEST\app\openidx-agent.exe`, `D:\openidx-test\app\openidx-agent.exe`, true},
		{`D:\other\openidx-agent.exe`, `D:\openidx-test\app\openidx-agent.exe`, false},
		{`{6D809377-6AF0-444B-8957-A3773F02200E}\Other\openidx-agent.exe`, `C:\Program Files\OpenIDX\openidx-agent.exe`, false},
		{`{00000000-0000-0000-0000-000000000000}\OpenIDX\openidx-agent.exe`, `C:\Program Files\OpenIDX\openidx-agent.exe`, false},
	}
	for _, c := range cases {
		if got := notifyIconPathMatches(c.stored, c.exe, folders); got != c.want {
			t.Errorf("notifyIconPathMatches(%q, %q) = %v, want %v", c.stored, c.exe, got, c.want)
		}
	}
}
