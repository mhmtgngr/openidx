package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// v204 adds two columns the SAML IdP reads on every sign-on. Their shapes are
// decisions: the encryption certificate is nullable because NULL is what
// "use the signing certificate" looks like, and the signing requirement
// defaults to false because that is what every registration does before the
// column exists.
func TestV204AddsTheSAMLEncryptionCertificateAndSigningRequirement(t *testing.T) {
	up := samlSPSigningAndEncryptionUp

	require.Contains(t, up,
		"ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS encryption_certificate TEXT;",
		"the encryption certificate is nullable: NULL means encrypt to the signing certificate")
	require.Contains(t, up,
		"ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS require_signed_authn_requests BOOLEAN NOT NULL DEFAULT false;",
		"an existing registration must keep accepting the unsigned requests it accepts today")
}

func TestV204DownRemovesBothColumns(t *testing.T) {
	require.Contains(t, samlSPSigningAndEncryptionDown, "DROP COLUMN IF EXISTS require_signed_authn_requests")
	require.Contains(t, samlSPSigningAndEncryptionDown, "DROP COLUMN IF EXISTS encryption_certificate")
}

func TestV204SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	var stmts []string
	for _, s := range m.splitSQL(samlSPSigningAndEncryptionUp) {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	require.Len(t, stmts, 2, "the up migration is two statements")
}
