package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestProbeVerifiesCertificatesUnlessAsked pins the one security decision this
// tool makes. It probes a live deployment to prove what that deployment really
// answers; a probe that accepts any certificate has not proved it reached the
// deployment it names. Skipping verification is therefore a thing the operator
// asks for with -insecure, never the default and never hard-coded.
func TestProbeVerifiesCertificatesUnlessAsked(t *testing.T) {
	if defaultInsecure {
		t.Error("-insecure defaults to on: contractcheck would silently accept any " +
			"certificate from the deployment it claims to have verified")
	}
	if probeTLS(defaultInsecure).InsecureSkipVerify {
		t.Error("the default probe transport skips certificate verification")
	}
	if !probeTLS(true).InsecureSkipVerify {
		t.Error("-insecure no longer reaches the transport: probing a self-signed " +
			"local edge would fail with no way to opt out")
	}
	for _, skip := range []bool{false, true} {
		if got := probeTLS(skip).MinVersion; got != tls.VersionTLS12 {
			t.Errorf("probeTLS(%v).MinVersion = %d, want TLS 1.2", skip, got)
		}
	}
}

func TestExtractKeys(t *testing.T) {
	cases := []struct {
		body string
		want []string
	}{
		{" policies: MFAPolicy[]; total: number ", []string{"policies", "total"}},
		{" settings: PasswordlessSettings ", []string{"settings"}},
		{" secrets: VaultSecretMeta[] | null ", []string{"secrets"}},
		{" data: Notification[] ", []string{"data"}},
		// nested generic must not leak inner keys as top-level
		{" risk: { avg: number; buckets: Array<{count:number}> } ", []string{"risk"}},
		{" count: number ", []string{"count"}},
	}
	for _, c := range cases {
		got := extractKeys(c.body)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("extractKeys(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

func TestScanFindsInlineObjectGets(t *testing.T) {
	dir := t.TempDir()
	src := `
import { api } from '../lib/api'
export function Page() {
  const a = api.get<{ policies: X[]; total: number }>('/api/v1/mfa/policies')
  const b = api.get<{ settings: S }>('/api/v1/identity/passwordless/settings')
  // skipped: named type
  const c = api.get<NamedType>('/api/v1/skipme')
  // skipped: template path
  const d = api.get<{ grants: G[] }>(` + "`/api/v1/x/${id}/grants`" + `)
  return null
}
`
	if err := os.WriteFile(filepath.Join(dir, "page.tsx"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	calls, skipped, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 static inline-object GET contracts, got %d: %+v", len(calls), calls)
	}
	byPath := map[string][]string{}
	for _, c := range calls {
		byPath[c.Path] = c.Keys
	}
	if got := byPath["/api/v1/mfa/policies"]; !reflect.DeepEqual(got, []string{"policies", "total"}) {
		t.Errorf("mfa/policies keys = %v", got)
	}
	if got := byPath["/api/v1/identity/passwordless/settings"]; !reflect.DeepEqual(got, []string{"settings"}) {
		t.Errorf("passwordless keys = %v", got)
	}
	// The named-type and template-path calls are counted as skipped, not matched.
	if skipped < 1 {
		t.Errorf("expected skipped >= 1 (named type + template path), got %d", skipped)
	}
}
