// Command identityplanes writes the identity-service plane manifest into the
// Helm chart, so the edge routing rules are generated from the same table the
// process registers routes with instead of being retyped next to it.
//
// Usage: go run ./tools/identityplanes
//
// TestPlaneManifestMatchesTheRouteTable fails when the file and the table have
// drifted, and names this command as the fix.
package main

import (
	"fmt"
	"os"

	"github.com/openidx/openidx/internal/identity"
)

const manifestPath = "deployments/kubernetes/helm/openidx/files/identity-planes.json"

func main() {
	b, err := identity.PlaneManifestJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "render manifest: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(manifestPath, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", manifestPath, err)
		os.Exit(1)
	}
	m := identity.BuildPlaneManifest()
	fmt.Printf("wrote %s (%d issue, %d admin)\n", manifestPath, len(m.Issue), len(m.Admin))
}
