package migrations

import (
	"strings"
	"testing"
)

// v179 adds the column a SAML metadata refresh has always written to.
//
// Without it the UPDATE in refreshSPMetadata could not plan, so the refresh
// failed entirely -- and with it the only path by which a service provider's
// rotated signing certificate reaches this database.
func TestMigrationV179_samlMetadataXML(t *testing.T) {
	m := migrationByVersion(t, 179)
	if m.Name != "saml_sp_metadata_xml" {
		t.Errorf("v179 Name = %q, want saml_sp_metadata_xml", m.Name)
	}
	if !strings.Contains(m.UpSQL, "ADD COLUMN IF NOT EXISTS metadata_xml TEXT") {
		t.Error("v179 does not add saml_service_providers.metadata_xml")
	}
	if !strings.Contains(m.DownSQL, "DROP COLUMN IF EXISTS metadata_xml") {
		t.Error("v179 Down does not drop the column")
	}
	// No NOT NULL and no backfill: nothing has ever stored a document, so NULL
	// is the honest value for every existing row.
	if strings.Contains(m.UpSQL, "NOT NULL") || strings.Contains(m.UpSQL, "UPDATE ") {
		t.Error("v179 backfills or constrains a column no row can have a value for")
	}
}

// The writer must still name the column, or the migration adds dead schema —
// the shape tools/tablewriters exists to catch, arrived at from the other side.
func TestV179WriterUsesTheColumn(t *testing.T) {
	src := mustReadFile(t, "../oauth/saml_metadata.go")
	if !strings.Contains(src, "metadata_xml = $4") {
		t.Error("the SP metadata refresh no longer writes metadata_xml; " +
			"v179 would be adding a column nothing uses")
	}
}
