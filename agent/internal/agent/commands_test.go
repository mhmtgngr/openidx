package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func untar(t *testing.T, data []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
	}
}

// The bundle carries the logs and agent.json, never the device's credential.
func TestCollectLogsRedactsAuthToken(t *testing.T) {
	dir := t.TempDir()
	cfg := &AgentConfig{ServerURL: "https://idp.example", AgentID: "agent-1", AuthToken: "s3cret-token-value",
		PushEnrollToken: "push-ticket-value"}
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "agent.log")
	if err := os.WriteFile(logPath, []byte("line one\nline two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, names, err := CollectLogs(dir, []string{logPath, filepath.Join(dir, "missing.log")})
	if err != nil {
		t.Fatal(err)
	}
	files := untar(t, data)
	if len(names) != 2 || files["agent.log"] != "line one\nline two\n" {
		t.Fatalf("bundle %v holds %v", names, files)
	}
	conf := files["agent.json"]
	if strings.Contains(conf, "s3cret-token-value") || strings.Contains(conf, "push-ticket-value") {
		t.Fatalf("the bundle carries a secret: %s", conf)
	}
	if !strings.Contains(conf, "[redacted]") || !strings.Contains(conf, "agent-1") {
		t.Errorf("agent.json was not kept with its secrets replaced: %s", conf)
	}
}

func TestTailFileKeepsTheEnd(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.log")
	if err := os.WriteFile(p, []byte("aaaaabbbbb"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := tailFile(p, 5)
	if err != nil || string(got) != "bbbbb" {
		t.Errorf("tail = %q, %v", got, err)
	}
}
