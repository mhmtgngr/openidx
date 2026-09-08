package docker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A secret the compose file does not pass is a secret the service does not have,
// and OpenIDX's answer to a missing ENCRYPTION_KEY is to carry on: internal
// secretcrypt falls back to a no-op cipher and logs a warning. So the OAuth
// signing key — the key that mints every token in the system — was stored in the
// database in PLAINTEXT on the reference stack and in the production compose
// file, while the same files refused to start without JWT_SECRET, a secret
// nothing signed or verified with.
//
// This derives the set of services that need the key from the tree rather than
// listing it: a package that reads Config.EncryptionKey needs it, and a binary
// that imports such a package needs it. A new service added next month is
// covered without anybody remembering this test exists.
func TestEveryServiceThatDecryptsIsGivenTheKey(t *testing.T) {
	root := repoRoot(t)

	readers := packagesReadingTheEncryptionKey(t, root)
	if len(readers) == 0 {
		t.Fatal("no package reads Config.EncryptionKey; the scan found nothing and every check below would pass vacuously")
	}

	for _, composeFile := range []string{"docker-compose.yml", "docker-compose.prod.yml"} {
		t.Run(composeFile, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, "deployments", "docker", composeFile))
			if err != nil {
				t.Fatalf("read %s: %v", composeFile, err)
			}
			services := serviceEnvironments(string(body))
			if len(services) == 0 {
				t.Fatalf("%s: no services parsed", composeFile)
			}

			checked := 0
			for name, env := range services {
				if _, err := os.Stat(filepath.Join(root, "cmd", name)); err != nil {
					continue // not one of our binaries (postgres, redis, apisix, …)
				}
				if !binaryImportsAny(t, root, name, readers) {
					continue
				}
				checked++
				if !strings.Contains(env, "ENCRYPTION_KEY") {
					t.Errorf("%s: service %q reads Config.EncryptionKey and the compose file does not pass ENCRYPTION_KEY. "+
						"Secrets it stores — the OAuth signing key, identity-provider client secrets, SMTP credentials — "+
						"are written in plaintext, and the only sign of it is a warning in the startup log.",
						composeFile, name)
				}
			}
			if checked == 0 {
				t.Errorf("%s: no service was checked; the mapping from compose service to cmd/ binary found nothing", composeFile)
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		// Not a git checkout: walk up to the module root instead.
		dir, _ := os.Getwd()
		for i := 0; i < 6; i++ {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
			dir = filepath.Dir(dir)
		}
		t.Fatalf("cannot locate the repository root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// packagesReadingTheEncryptionKey returns the import paths of packages whose
// non-test sources read the field.
func packagesReadingTheEncryptionKey(t *testing.T, root string) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", "list", "-f", "{{.ImportPath}} {{.Dir}}", "./...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	readers := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		path, dir, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			src, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			// The config package declares and validates the field; declaring it
			// is not consuming it, and config is imported by everything.
			if path == "github.com/openidx/openidx/internal/common/config" {
				continue
			}
			if strings.Contains(string(src), ".EncryptionKey") {
				readers[path] = true
				break
			}
		}
	}
	return readers
}

func binaryImportsAny(t *testing.T, root, binary string, readers map[string]bool) bool {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "./cmd/"+binary)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		// Not a Go binary at all: cmd/simple-web is an nginx image's document
		// root. A directory under cmd/ with no Go files decrypts nothing.
		return false
	}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if readers[dep] {
			return true
		}
	}
	return false
}

// serviceEnvironments splits a compose file into service name -> that service's
// block. Textual rather than a YAML decode so the assertion is about what an
// operator reads in the file, `${VAR:?…}` interpolation included.
func serviceEnvironments(compose string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(compose, "\n")
	inServices := false
	current := ""
	var body strings.Builder
	flush := func() {
		if current != "" {
			out[current] = body.String()
		}
		body.Reset()
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, " ") && strings.HasPrefix(line, "services:") {
			inServices = true
			continue
		}
		if !inServices {
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") {
			flush()
			current = ""
			inServices = false
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") &&
			strings.HasSuffix(strings.TrimSpace(line), ":") {
			flush()
			current = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		body.WriteString(line)
		body.WriteString("\n")
	}
	flush()
	return out
}
