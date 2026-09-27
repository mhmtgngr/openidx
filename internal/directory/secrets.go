package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// DIRECTORY CREDENTIALS AT REST.
//
// directory_integrations.config holds the credential each connector signs in
// with: the LDAP or Active Directory bind password, the Azure AD client secret
// and the HR system's API key. They were stored as they arrived, readable by
// anything that could read the table, a backup or a replica, and GET
// /api/v1/directories and /directories/:id returned them.
//
// Each is now sealed with the ENCRYPTION_KEY cipher before it is stored, and
// tagged, so cmd/rekey reseals it inside the JSON when a key is rotated out.
// Only the code that signs in with it opens it: the connection test and the
// diagnostics (internal/admin), the sync jobs (Scheduler.loadDirectoryConfig)
// and the login pass-through, password change and reset the identity and
// oauth services make (Service.loadDirectoryTypeAndConfig). No read returns
// it: <key>_set says whether one is stored.
//
// A credential stored in plaintext by an earlier release is untagged, and an
// untagged value is used as it is, so it keeps working. It is sealed by the
// next save of its directory, and by SealStoredSecrets, which admin-api runs
// at startup, where the key is.

// secretKeys are the config keys that hold a credential, whatever the type.
var secretKeys = []string{"bind_password", "client_secret", "api_key"}

// SecretKeyFor returns the config key that holds the credential a directory
// type signs in with, or "" for a type that has none.
func SecretKeyFor(dirType string) string {
	switch dirType {
	case "ldap", "active_directory":
		return "bind_password"
	case "azure_ad":
		return "client_secret"
	case "hris", "bamboohr":
		return "api_key"
	}
	return ""
}

// SecretSetKey is the key a read carries in place of a credential: true when
// one is stored.
func SecretSetKey(key string) string { return key + "_set" }

func secretLabel(key string) string {
	switch key {
	case "bind_password":
		return "bind password"
	case "client_secret":
		return "client secret"
	case "api_key":
		return "API key"
	}
	return key
}

// UnopenableSecretError says a stored credential is sealed and this service's
// ENCRYPTION_KEY cannot open it: the key was rotated out without cmd/rekey, or
// the service has none. It is refused rather than used: sent as it is, the
// sealed value is a wrong credential, and a directory server counts each one
// toward the service account's lockout.
type UnopenableSecretError struct{ Key string }

func (e *UnopenableSecretError) Error() string {
	return fmt.Sprintf("the stored %s cannot be decrypted with this service's ENCRYPTION_KEY; save the directory again with it",
		secretLabel(e.Key))
}

// SealSecrets seals, in place, every credential in cfg that is not sealed
// yet. A cipher without a key (no ENCRYPTION_KEY) leaves them as they are. A
// value that is already sealed is one carried from the stored config: a
// sealed value from a client is refused before this (SealedInput).
func SealSecrets(c *secretcrypt.Cipher, cfg map[string]any) error {
	if c == nil {
		return nil
	}
	for _, k := range secretKeys {
		v, ok := cfg[k].(string)
		if !ok || v == "" || secretcrypt.IsEncrypted(v) {
			continue
		}
		sealed, err := c.Encrypt(v)
		if err != nil {
			return fmt.Errorf("seal the %s: %w", secretLabel(k), err)
		}
		cfg[k] = sealed
	}
	return nil
}

// RedactSecrets takes every credential out of cfg and, for each the config
// holds, says whether one is stored.
func RedactSecrets(cfg map[string]any) {
	for _, k := range secretKeys {
		v, ok := cfg[k]
		if !ok {
			continue
		}
		s, _ := v.(string)
		delete(cfg, k)
		cfg[SecretSetKey(k)] = s != ""
	}
}

// StripSecretFlags removes the <key>_set flags a read adds, so a client that
// sends a read back does not store them.
func StripSecretFlags(cfg map[string]any) {
	for _, k := range secretKeys {
		delete(cfg, SecretSetKey(k))
	}
}

// SealedInput returns, as field errors, the credentials in a config from a
// client that are sealed values. A client never holds one, since no read
// returns it; opening one it supplied would decrypt a credential sealed for
// another directory, perhaps another organization's, and hand it to a server
// of the sender's choosing.
func SealedInput(cfg map[string]any) map[string]string {
	errs := map[string]string{}
	for _, k := range secretKeys {
		if v, ok := cfg[k].(string); ok && secretcrypt.IsEncrypted(v) {
			errs["config."+k] = fmt.Sprintf("Send the %s itself; a sealed value is not accepted.", secretLabel(k))
		}
	}
	return errs
}

// OpenSecrets returns configBytes with every credential opened, for the code
// that signs in with it. An untagged value, stored before sealing, comes back
// as it is. A sealed value the cipher cannot open is an
// *UnopenableSecretError.
func OpenSecrets(c *secretcrypt.Cipher, configBytes []byte) ([]byte, error) {
	cfg, err := decodeConfig(configBytes)
	if err != nil {
		// Not an object, so it holds no credential; the typed decode that
		// follows reports what is wrong with it.
		return configBytes, nil
	}
	changed := false
	for _, k := range secretKeys {
		v, ok := cfg[k].(string)
		if !ok || !secretcrypt.IsEncrypted(v) {
			continue
		}
		plaintext, err := openSecret(c, k, v)
		if err != nil {
			return nil, err
		}
		cfg[k] = plaintext
		changed = true
	}
	if !changed {
		return configBytes, nil
	}
	return json.Marshal(cfg)
}

func openSecret(c *secretcrypt.Cipher, key, stored string) (string, error) {
	if !secretcrypt.IsEncrypted(stored) {
		return stored, nil
	}
	if c == nil {
		return "", &UnopenableSecretError{Key: key}
	}
	plaintext, err := c.Decrypt(stored)
	// A cipher without a key hands a sealed value back as it is.
	if err != nil || secretcrypt.IsEncrypted(plaintext) {
		return "", &UnopenableSecretError{Key: key}
	}
	return plaintext, nil
}

// refuseSealed is the connectors' side of the same rule: a credential that
// reaches them still sealed was not opened by whoever loaded it, and is not
// sent.
func refuseSealed(configBytes []byte) error {
	cfg, err := decodeConfig(configBytes)
	if err != nil {
		return nil // the typed decode that follows reports it
	}
	for _, k := range secretKeys {
		if v, ok := cfg[k].(string); ok && secretcrypt.IsEncrypted(v) {
			return fmt.Errorf("the %s is still sealed; it has to be opened before it is sent", secretLabel(k))
		}
	}
	return nil
}

// KeepStoredSecret gives an update that leaves the credential out (absent or
// empty) the stored one, as a form that leaves a password field blank means
// "unchanged", since no read returns it to send back. Only for the same type
// and the same target: a credential belongs to the account and the server it
// was entered for, and carried to a server the caller chose, it would be
// handed to whoever answers there. What counts as the target is SameTarget's.
//
// It returns a field error when the credential is needed and cannot be kept:
// the target changed, or the stored one cannot be opened. It does not open
// what it carries; the caller seals the config before storing it, which seals
// a credential stored in plaintext by an earlier release.
func KeepStoredSecret(c *secretcrypt.Cipher, storedType string, storedConfig []byte, dirType string, next map[string]any) map[string]string {
	key := SecretKeyFor(dirType)
	if key == "" {
		return nil
	}
	if v, _ := next[key].(string); v != "" {
		return nil
	}
	if storedType != dirType {
		return nil
	}
	stored, err := decodeConfig(storedConfig)
	if err != nil {
		return nil
	}
	sv, _ := stored[key].(string)
	if sv == "" {
		return nil
	}
	if !SameTarget(dirType, stored, next) {
		return map[string]string{"config." + key: fmt.Sprintf(
			"%s is required: the stored one is kept only while %s stay the same.",
			capitalize(secretLabel(key)), targetFields(dirType))}
	}
	if _, err := openSecret(c, key, sv); err != nil {
		return map[string]string{"config." + key: fmt.Sprintf(
			"The stored %s cannot be decrypted with this service's ENCRYPTION_KEY; send it again.", secretLabel(key))}
	}
	next[key] = sv
	return nil
}

// SameTarget reports whether two configs of a directory type send its
// credential to the same place, the same way, as the same account:
//   - LDAP and Active Directory: the host, port and bind DN, and what else
//     decides where and how the bind password travels: implicit TLS, StartTLS,
//     certificate verification, and whether and how far referrals are
//     followed, since a followed referral binds on a host the directory
//     server names;
//   - Azure AD: the tenant and client ID;
//   - an HR system: the provider and the base URL the key is sent to, the
//     subdomain's default gateway when no base URL is set.
func SameTarget(dirType string, a, b map[string]any) bool {
	switch dirType {
	case "ldap", "active_directory":
		return strings.EqualFold(cfgString(a, "host"), cfgString(b, "host")) &&
			cfgNumber(a, "port") == cfgNumber(b, "port") &&
			strings.EqualFold(cfgString(a, "bind_dn"), cfgString(b, "bind_dn")) &&
			cfgBool(a, "use_tls") == cfgBool(b, "use_tls") &&
			cfgBool(a, "start_tls") == cfgBool(b, "start_tls") &&
			cfgBool(a, "skip_tls_verify") == cfgBool(b, "skip_tls_verify") &&
			cfgBool(a, "follow_referrals") == cfgBool(b, "follow_referrals") &&
			cfgNumber(a, "referral_hop_limit") == cfgNumber(b, "referral_hop_limit")
	case "azure_ad":
		return strings.EqualFold(cfgString(a, "tenant_id"), cfgString(b, "tenant_id")) &&
			strings.EqualFold(cfgString(a, "client_id"), cfgString(b, "client_id"))
	case "hris", "bamboohr":
		return hrisProvider(a) == hrisProvider(b) && hrisEndpoint(a) == hrisEndpoint(b)
	}
	return false
}

func targetFields(dirType string) string {
	switch dirType {
	case "ldap", "active_directory":
		return "the host, port, bind DN, TLS and referral settings"
	case "azure_ad":
		return "the tenant and client ID"
	case "hris", "bamboohr":
		return "the provider, base URL and subdomain"
	}
	return "the connection settings"
}

func hrisProvider(cfg map[string]any) string {
	p := strings.ToLower(cfgString(cfg, "provider"))
	if p == "" {
		return "bamboohr"
	}
	return p
}

// hrisEndpoint is where the API key is sent; NewBambooHRConnector resolves it
// the same way.
func hrisEndpoint(cfg map[string]any) string {
	return bambooHRBaseURL(cfgString(cfg, "base_url"), cfgString(cfg, "subdomain"))
}

// SealStoredSecrets seals every credential still stored in plaintext, across
// every organization's directories, and returns how many directories it
// sealed. Each row is updated only while its config is still what was read,
// so replicas starting together seal it once and a save made meanwhile is not
// overwritten. Without a key there is nothing to seal with: SealSecrets
// leaves each value as it is, and no row is written.
func (s *Service) SealStoredSecrets(ctx context.Context) (int, error) {
	if s.cipher == nil {
		return 0, nil
	}
	ctx = orgctx.WithBypassRLS(ctx)
	type row struct {
		id, orgID string
		config    []byte
	}
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore startup sweep over every organization's directories; each row is then updated under its own org_id
		`SELECT id::text, org_id::text, config FROM directory_integrations WHERE config ?| $1::text[]`, secretKeys)
	if err != nil {
		return 0, fmt.Errorf("list the directories' stored credentials: %w", err)
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.orgID, &r.config); err != nil {
			rows.Close()
			return 0, fmt.Errorf("read a directory's stored credentials: %w", err)
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("list the directories' stored credentials: %w", err)
	}

	sealed := 0
	for _, r := range pending {
		done, err := s.sealStoredRow(ctx, r.id, r.orgID, r.config)
		if err != nil {
			return sealed, err
		}
		if done {
			sealed++
		}
	}
	return sealed, nil
}

// sealStoredRow seals the plaintext credentials of one directory's config as
// it was read, and writes it only while the row still holds exactly that: a
// save made since was sealed when it was saved and is not overwritten with
// the credential it replaced, and a row another replica sealed first is left
// as that replica left it.
func (s *Service) sealStoredRow(ctx context.Context, id, orgID string, read []byte) (bool, error) {
	cfg, err := decodeConfig(read)
	if err != nil {
		s.logger.Warn("a directory's config is not a JSON object; its credentials are left as they are",
			zap.String("directory_id", id), zap.Error(err))
		return false, nil
	}
	before, err := json.Marshal(cfg)
	if err != nil {
		return false, err
	}
	if err := SealSecrets(s.cipher, cfg); err != nil {
		return false, err
	}
	after, err := json.Marshal(cfg)
	if err != nil {
		return false, err
	}
	if bytes.Equal(before, after) {
		return false, nil
	}
	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE directory_integrations SET config = $1::jsonb
		  WHERE id = $2 AND org_id = $3 AND config = $4::jsonb`,
		string(after), id, orgID, string(read))
	if err != nil {
		return false, fmt.Errorf("seal directory %s's credentials: %w", id, err)
	}
	return tag.RowsAffected() == 1, nil
}

// decodeConfig decodes a config object keeping its numbers as written, so a
// config that is only re-encoded does not change.
func decodeConfig(configBytes []byte) (map[string]any, error) {
	cfg := map[string]any{}
	if len(bytes.TrimSpace(configBytes)) == 0 {
		return cfg, nil
	}
	dec := json.NewDecoder(bytes.NewReader(configBytes))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("directory config is not a JSON object: %w", err)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, nil
}

func cfgString(cfg map[string]any, key string) string {
	s, _ := cfg[key].(string)
	return strings.TrimSpace(s)
}

func cfgBool(cfg map[string]any, key string) bool {
	b, _ := cfg[key].(bool)
	return b
}

// cfgNumber renders a number the same way whether it was decoded as a
// float64 (a request body) or a json.Number (a stored config).
func cfgNumber(cfg map[string]any, key string) string {
	switch v := cfg[key].(type) {
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return strconv.FormatFloat(f, 'f', -1, 64)
		}
		return v.String()
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	}
	return fmt.Sprint(cfg[key])
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
