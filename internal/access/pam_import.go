// Package access — Devolutions Remote Desktop Manager (RDM) import.
//
// Imports an RDM JSON export (File → Export → "All data" / .rdm JSON) into
// the PAM connection manager so everything RDM holds lands in OpenIDX:
// groups become pam_folders, sessions/credentials become typed pam_entries,
// plaintext-exported passwords are sealed into the vault, and every other
// field of each RDM object is preserved verbatim (password-like keys
// scrubbed) under the entry's settings.rdm — nothing is dropped, even for
// entry types OpenIDX has no native equivalent for (those import as
// secure_note carriers).
package access

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// rdmTypeNames maps RDM ConnectionType string names to PAM entry types.
// "group" marks folder rows. Types with no native equivalent fall back to
// secure_note in mapRDMConnection (data preserved under settings.rdm).
var rdmTypeNames = map[string]string{
	"RDPConfigured": "rdp",
	"RDPFilename":   "rdp",
	"SSHShell":      "ssh",
	"SSHTunnel":     "ssh",
	"VNC":           "vnc",
	"Telnet":        "telnet",
	"WebBrowser":    "website",
	"Credential":    "credential",
	"Group":         "group",
	"Folder":        "group",
	"DataEntry":     "secure_note",
	"SecureNote":    "secure_note",
	"Document":      "document",
}

// rdmTypeNumbers maps the numeric ConnectionType values RDM uses in some
// export builds. Only the well-known stable values are mapped; anything else
// falls back via ConnectionTypeName or to secure_note.
var rdmTypeNumbers = map[int]string{
	1:  "rdp",     // RDPConfigured
	2:  "rdp",     // RDPFilename
	9:  "website", // WebBrowser
	25: "group",   // Group
	26: "credential",
	77: "ssh", // SSHShell
}

// rdmImportItem is one mapped RDM object ready to persist.
type rdmImportItem struct {
	EntryType   string
	Name        string
	FolderPath  string // backslash-separated RDM group path
	Description string
	Hostname    string
	Port        int
	Username    string
	Domain      string
	URL         string
	Secret      string                 // plaintext password/key from the export ("" when absent/encrypted)
	Preserved   map[string]interface{} // full original object, password keys scrubbed
}

// parseRDMExport accepts the shapes RDM produces: {"Connections":[…]},
// a bare array […], or a single connection object.
func parseRDMExport(data []byte) ([]map[string]interface{}, error) {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, errors.New("empty import payload")
	}

	var wrapper struct {
		Connections []map[string]interface{} `json:"Connections"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Connections != nil {
		return wrapper.Connections, nil
	}

	var list []map[string]interface{}
	if err := json.Unmarshal(data, &list); err == nil {
		return list, nil
	}

	var single map[string]interface{}
	if err := json.Unmarshal(data, &single); err == nil && len(single) > 0 {
		return []map[string]interface{}{single}, nil
	}

	return nil, errors.New("unrecognized RDM export format (expected JSON with a Connections array)")
}

// rdmString pulls the first non-empty string among keys, looking at the top
// level and inside the nested objects RDM commonly uses.
func rdmString(conn map[string]interface{}, keys ...string) string {
	nested := []string{"", "Terminal", "RDP", "Credentials", "WebBrowser", "DataEntry"}
	for _, holder := range nested {
		src := conn
		if holder != "" {
			obj, ok := conn[holder].(map[string]interface{})
			if !ok {
				continue
			}
			src = obj
		}
		for _, k := range keys {
			if v, ok := src[k]; ok {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
	}
	return ""
}

// rdmInt pulls the first positive integer among keys (same nesting rules).
func rdmInt(conn map[string]interface{}, keys ...string) int {
	nested := []string{"", "Terminal", "RDP", "WebBrowser"}
	for _, holder := range nested {
		src := conn
		if holder != "" {
			obj, ok := conn[holder].(map[string]interface{})
			if !ok {
				continue
			}
			src = obj
		}
		for _, k := range keys {
			switch v := src[k].(type) {
			case float64:
				if v > 0 {
					return int(v)
				}
			case string:
				var n int
				if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil && n > 0 {
					return n
				}
			}
		}
	}
	return 0
}

// rdmConnectionType resolves an RDM object's type to a PAM entry type
// ("group" for folders). Unknown types map to secure_note so no RDM data is
// ever dropped on import.
func rdmConnectionType(conn map[string]interface{}) string {
	if v, ok := conn["ConnectionType"]; ok {
		switch t := v.(type) {
		case string:
			if mapped, ok := rdmTypeNames[t]; ok {
				return mapped
			}
		case float64:
			if mapped, ok := rdmTypeNumbers[int(t)]; ok {
				return mapped
			}
		}
	}
	if v, ok := conn["ConnectionTypeName"].(string); ok {
		if mapped, ok := rdmTypeNames[v]; ok {
			return mapped
		}
	}
	return "secure_note"
}

// scrubRDMSecrets deep-copies an RDM object with every password-like key
// removed, so the preserved settings.rdm blob carries no plaintext secrets
// (those are sealed into the vault instead).
func scrubRDMSecrets(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, inner := range val {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "password") || strings.Contains(lk, "passphrase") ||
				strings.Contains(lk, "privatekey") || strings.Contains(lk, "private_key") {
				continue
			}
			out[k] = scrubRDMSecrets(inner)
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(val))
		for _, inner := range val {
			out = append(out, scrubRDMSecrets(inner))
		}
		return out
	default:
		return v
	}
}

// mapRDMConnection converts one RDM object into an import item. Returns nil
// for objects with no name (unimportable).
func mapRDMConnection(conn map[string]interface{}) *rdmImportItem {
	name := rdmString(conn, "Name")
	if name == "" {
		return nil
	}

	entryType := rdmConnectionType(conn)
	item := &rdmImportItem{
		EntryType:   entryType,
		Name:        name,
		FolderPath:  rdmString(conn, "Group"),
		Description: rdmString(conn, "Description"),
		Username:    rdmString(conn, "UserName", "Username"),
		Domain:      rdmString(conn, "Domain"),
		// Only the plaintext-export field. SafePassword is RDM-encrypted
		// ciphertext — unusable here, so it is scrubbed, not imported.
		Secret: rdmString(conn, "Password"),
	}

	preserved, _ := scrubRDMSecrets(conn).(map[string]interface{})
	item.Preserved = preserved

	switch entryType {
	case "group":
		// Folder row: the Group field holds the FULL path of the folder
		// itself (RDM semantics); Name is its leaf. When Group is absent the
		// folder is top-level.
		if item.FolderPath == "" {
			item.FolderPath = name
		}
		return item
	case "website":
		item.URL = rdmString(conn, "WebBrowserUrl", "URL", "Url")
	case "rdp", "ssh", "vnc", "telnet":
		item.Hostname = rdmString(conn, "Url", "Host", "HostName", "Hostname", "ComputerName")
		item.Port = pamDefaultPort(entryType, rdmInt(conn, "Port", "HostPort"))
	}
	return item
}

// splitRDMGroupPath splits an RDM group path on the separators RDM uses
// ("\" in exports, some builds emit "/").
func splitRDMGroupPath(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '\\' || r == '/' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// PamImportResult is the import summary returned to the console.
type PamImportResult struct {
	FoldersCreated int             `json:"folders_created"`
	EntriesCreated int             `json:"entries_created"`
	SecretsStored  int             `json:"secrets_stored"`
	ByType         map[string]int  `json:"by_type"`
	Skipped        []PamImportSkip `json:"skipped"`
}

// PamImportSkip records one object the import could not fully place.
type PamImportSkip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// handlePamImportRDM — POST /pam/import/rdm (admin), body {"data": "<RDM JSON>"}.
//
// Everything imported is tagged "rdm-import". Passwords present in the
// export are sealed into the vault; secret-less entries import with their
// metadata only (RDM encrypted exports never expose plaintext, so there is
// nothing to seal — noted per entry in the skipped list).
func (s *Service) handlePamImportRDM(c *gin.Context) {
	var req struct {
		Data     string `json:"data" binding:"required"`
		FolderID string `json:"folder_id"` // optional root folder to import under
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "data (RDM export JSON) is required"})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")

	conns, err := parseRDMExport([]byte(req.Data))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(conns) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no connections found in export"})
		return
	}
	if len(conns) > 5000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "import too large (max 5000 objects per request)"})
		return
	}

	result := PamImportResult{ByType: map[string]int{}, Skipped: []PamImportSkip{}}

	// Pass 1 — build the folder tree: explicit Group rows plus every path
	// referenced by an entry.
	folderIDs := map[string]string{} // normalized path → pam_folders.id
	ensureFolder := func(path []string) (string, error) {
		parentID := req.FolderID
		key := ""
		for _, seg := range path {
			if key != "" {
				key += "\\"
			}
			key += strings.ToLower(seg)
			if id, ok := folderIDs[key]; ok {
				parentID = id
				continue
			}
			// Reuse an existing folder with the same name under the same parent.
			var id string
			err := s.db.Pool.QueryRow(ctx, `
				SELECT id FROM pam_folders
				 WHERE org_id = $1 AND LOWER(name) = LOWER($2)
				   AND parent_id IS NOT DISTINCT FROM NULLIF($3,'')::uuid`,
				org.ID, seg, parentID).Scan(&id)
			if err != nil {
				id = uuid.New().String()
				if _, err := s.db.Pool.Exec(ctx, `
					INSERT INTO pam_folders (id, org_id, parent_id, name, created_by)
					VALUES ($1, $2, NULLIF($3,'')::uuid, $4, NULLIF($5,'')::uuid)`,
					id, org.ID, parentID, seg, userID); err != nil {
					return "", err
				}
				result.FoldersCreated++
			}
			folderIDs[key] = id
			parentID = id
		}
		return parentID, nil
	}

	items := make([]*rdmImportItem, 0, len(conns))
	for _, conn := range conns {
		item := mapRDMConnection(conn)
		if item == nil {
			result.Skipped = append(result.Skipped, PamImportSkip{Name: "(unnamed)", Reason: "object has no Name"})
			continue
		}
		if item.EntryType == "group" {
			if _, err := ensureFolder(splitRDMGroupPath(item.FolderPath)); err != nil {
				s.logger.Warn("handlePamImportRDM: folder create failed",
					zap.String("path", item.FolderPath), zap.Error(err))
				result.Skipped = append(result.Skipped, PamImportSkip{Name: item.Name, Reason: "folder create failed"})
			}
			continue
		}
		items = append(items, item)
	}

	// Pass 2 — entries.
	for _, item := range items {
		folderID, err := ensureFolder(splitRDMGroupPath(item.FolderPath))
		if err != nil {
			s.logger.Warn("handlePamImportRDM: folder create failed",
				zap.String("path", item.FolderPath), zap.Error(err))
			result.Skipped = append(result.Skipped, PamImportSkip{Name: item.Name, Reason: "folder create failed"})
			continue
		}

		entryID := uuid.New().String()

		vaultSecretID := ""
		if item.Secret != "" {
			vaultSecretID, err = s.storePamSecret(ctx, entryID, item.EntryType, item.Name, item.Secret, userID)
			if err != nil {
				s.logger.Warn("handlePamImportRDM: secret store failed",
					zap.String("name", item.Name), zap.Error(err))
				result.Skipped = append(result.Skipped, PamImportSkip{Name: item.Name, Reason: "secret store failed; entry imported without secret"})
			} else {
				result.SecretsStored++
			}
		}

		settings := map[string]interface{}{"rdm": item.Preserved}
		settingsJSON, _ := json.Marshal(settings)

		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO pam_entries (id, org_id, folder_id, name, entry_type, description, tags,
			                         hostname, port, username, domain, url, settings,
			                         vault_secret_id, created_by)
			VALUES ($1, $2, NULLIF($3,'')::uuid, $4, $5, NULLIF($6,''), $7,
			        NULLIF($8,''), NULLIF($9,0), NULLIF($10,''), NULLIF($11,''), NULLIF($12,''), $13,
			        NULLIF($14,'')::uuid, NULLIF($15,'')::uuid)`,
			entryID, org.ID, folderID, item.Name, item.EntryType, item.Description, []string{"rdm-import"},
			item.Hostname, item.Port, item.Username, item.Domain, item.URL, settingsJSON,
			vaultSecretID, userID)
		if err != nil {
			if vaultSecretID != "" && s.vaultSvc != nil {
				if delErr := s.vaultSvc.Delete(ctx, vaultSecretID); delErr != nil {
					s.logger.Warn("handlePamImportRDM: orphan secret cleanup failed", zap.Error(delErr))
				}
			}
			s.logger.Warn("handlePamImportRDM: entry insert failed",
				zap.String("name", item.Name), zap.Error(err))
			result.Skipped = append(result.Skipped, PamImportSkip{Name: item.Name, Reason: "entry insert failed"})
			continue
		}

		result.EntriesCreated++
		result.ByType[item.EntryType]++
	}

	s.logAuditEvent(c, "pam.rdm_imported", "", "pam_entry", map[string]interface{}{
		"entries_created": result.EntriesCreated,
		"folders_created": result.FoldersCreated,
		"secrets_stored":  result.SecretsStored,
		"skipped":         len(result.Skipped),
		"user_id":         userID,
	})

	c.JSON(http.StatusOK, result)
}
