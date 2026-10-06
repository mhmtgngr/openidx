package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// Device keys.
//
// An agent proved itself with one bearer token, readable by every signed-in
// user of a Windows machine. The desktop agent now keeps an ECDSA P-256 key
// the operating system will not export (agent/internal/devicekey: the TPM, or
// the software key store, or a file off Windows) and signs its posture
// reports with it. The server stores the public half at enrolment, or from
// the agent's own registration, signed by that key, for a device that
// enrolled before it had one. From then on a report from the device must
// carry a valid signature: a copy of the token is no longer enough to speak
// for the device.

// deviceKeyRequest is an agent's public key as enrolment and registration
// carry it.
type deviceKeyRequest struct {
	PublicKey string `json:"public_key"`
	Kind      string `json:"kind"`
}

const (
	// agentRequestDomain must equal devicekey.requestDomain in the agent.
	agentRequestDomain = "openidx-agent-request/v1"
	// agentSignatureWindow bounds how far a signature's timestamp may be from
	// the server's clock either way. It bounds the replay of a captured
	// report as well as clock skew.
	agentSignatureWindow = 5 * time.Minute
	// maxAgentReportBytes bounds a report body read whole for its signature.
	maxAgentReportBytes = 4 << 20
)

// Header names, as the agent sends them.
const (
	headerAgentKeyTimestamp = "X-Agent-Key-Timestamp"
	headerAgentKeySignature = "X-Agent-Key-Signature"
)

var errDeviceSignatureMissing = errors.New("this device's reports must be signed with its device key")

// parseDeviceKey accepts an ECDSA P-256 public key in base64 PKIX DER, of a
// kind the agent can have.
func parseDeviceKey(req deviceKeyRequest) (*ecdsa.PublicKey, string, error) {
	switch req.Kind {
	case "tpm", "software", "file":
	default:
		return nil, "", fmt.Errorf("unknown device key kind %q", req.Kind)
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PublicKey))
	if err != nil {
		return nil, "", errors.New("device key is not base64")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", errors.New("device key is not a PKIX public key")
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, "", errors.New("device key is not an ECDSA P-256 key")
	}
	return pub, req.Kind, nil
}

// agentRequestSigningInput is the byte string an agent signs; it must match
// devicekey.RequestSigningInput in the agent byte for byte.
func agentRequestSigningInput(method, path, agentID string, unixTime int64, body []byte) ([]byte, error) {
	for _, v := range []string{method, path, agentID} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("a signed request field contains a line break")
		}
	}
	sum := sha256.Sum256(body)
	return []byte(agentRequestDomain + "\n" + method + "\n" + path + "\n" + agentID + "\n" +
		strconv.FormatInt(unixTime, 10) + "\n" + hex.EncodeToString(sum[:]) + "\n"), nil
}

// verifyAgentRequestSignature checks a request's device-key signature. A
// missing signature is errDeviceSignatureMissing; anything else wrong is a
// plain error.
func verifyAgentRequestSignature(pub *ecdsa.PublicKey, method, path, agentID string, body []byte, tsHeader, sigHeader string, now time.Time) error {
	tsHeader, sigHeader = strings.TrimSpace(tsHeader), strings.TrimSpace(sigHeader)
	if tsHeader == "" || sigHeader == "" {
		return errDeviceSignatureMissing
	}
	unix, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return errors.New("the signature's timestamp is not a number")
	}
	if d := now.Sub(time.Unix(unix, 0)); d > agentSignatureWindow || d < -agentSignatureWindow {
		return errors.New("the signature's timestamp is outside the accepted window")
	}
	sig, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil {
		return errors.New("the signature is not base64")
	}
	input, err := agentRequestSigningInput(method, path, agentID, unix, body)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(input)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("the signature does not verify against the device key")
	}
	return nil
}

// agentDeviceKey returns the key the server holds for an agent, or nil.
func (h *AgentAPIHandler) agentDeviceKey(ctx context.Context, agentID string) (*ecdsa.PublicKey, error) {
	var b64, kind string
	if err := h.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(device_public_key,''), COALESCE(device_key_kind,'')
		  FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`,
		agentID, orgIDFrom(ctx)).Scan(&b64, &kind); err != nil {
		return nil, err
	}
	if b64 == "" {
		return nil, nil
	}
	pub, _, err := parseDeviceKey(deviceKeyRequest{PublicKey: b64, Kind: kind})
	if err != nil {
		return nil, fmt.Errorf("the stored device key is unusable: %w", err)
	}
	return pub, nil
}

// setAgentDeviceKey records the key an enrolment named, or clears it when the
// enrolment named none: the enrolment is the authority on the device, and a
// key left from before it could be one the device no longer holds.
func (h *AgentAPIHandler) setAgentDeviceKey(ctx context.Context, agentID string, req *deviceKeyRequest) bool {
	if h.db == nil || h.db.Pool == nil || agentID == "" {
		return false
	}
	var b64, kind string
	if req != nil {
		if _, k, err := parseDeviceKey(*req); err == nil {
			b64, kind = strings.TrimSpace(req.PublicKey), k
		} else {
			// The error quotes the kind the enrolment sent, so it is request
			// text and goes through logsafe like any other.
			h.logger.Warn("enrolment named a device key that is not usable; enrolling without one",
				logsafe.String("agent_id", agentID), logsafe.String("error", err.Error()))
		}
	}
	if _, err := h.db.Pool.Exec(ctx, `
		UPDATE enrolled_agents
		   SET device_public_key = NULLIF($3,''), device_key_kind = NULLIF($4,''),
		       device_key_bound_at = CASE WHEN $3 = '' THEN NULL ELSE NOW() END
		 WHERE agent_id = $1 AND org_id = $2`,
		agentID, orgIDFrom(ctx), b64, kind); err != nil {
		h.logger.Warn("could not record the device key named at enrolment",
			logsafe.String("agent_id", agentID), zap.Error(err))
		return false
	}
	return b64 != ""
}

// HandleRegisterDeviceKey — POST /agent/device-key. An enrolled agent with no
// key on record offers its key, in a request signed by that key, so the
// server stores one the caller proves it holds. The same key again is a
// no-op; a different key is refused, because replacing a device's key is
// what enrolment is for.
func (h *AgentAPIHandler) HandleRegisterDeviceKey(c *gin.Context) {
	agentID, ok := h.requireEnrolledAgent(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 64<<10))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	var req deviceKeyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse body"})
		return
	}
	pub, kind, err := parseDeviceKey(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "device_key_invalid"})
		return
	}
	if err := verifyAgentRequestSignature(pub, c.Request.Method, c.Request.URL.Path, agentID, body,
		c.GetHeader(headerAgentKeyTimestamp), c.GetHeader(headerAgentKeySignature), time.Now()); err != nil {
		h.logAuditEvent("agent.device_key_refused", agentID, "denied", err.Error())
		h.logAuditEventToDB(ctx, "agent.device_key_refused", agentID, "denied", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "the key's own signature is required: " + err.Error(),
			"code": "device_signature_invalid"})
		return
	}
	held, err := h.agentDeviceKey(ctx, agentID)
	if err != nil {
		h.logger.Error("device key lookup failed", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read the device"})
		return
	}
	if held != nil {
		if held.Equal(pub) {
			c.JSON(http.StatusOK, gin.H{"device_key_bound": true})
			return
		}
		h.logAuditEvent("agent.device_key_refused", agentID, "denied", "a different key is already bound")
		h.logAuditEventToDB(ctx, "agent.device_key_refused", agentID, "denied", "a different key is already bound")
		c.JSON(http.StatusConflict, gin.H{"error": "this device already has a different key; enrol it again to replace it",
			"code": "device_key_conflict"})
		return
	}
	// The predicate keeps two concurrent registrations from both winning.
	tag, err := h.db.Pool.Exec(ctx, `
		UPDATE enrolled_agents
		   SET device_public_key = $3, device_key_kind = $4, device_key_bound_at = NOW()
		 WHERE agent_id = $1 AND org_id = $2 AND device_public_key IS NULL`,
		agentID, orgIDFrom(ctx), strings.TrimSpace(req.PublicKey), kind)
	if err != nil {
		h.logger.Error("storing the device key failed", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store the device key"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "this device already has a key", "code": "device_key_conflict"})
		return
	}
	h.logAuditEvent("agent.device_key_bound", agentID, "success", "kind="+kind)
	h.logAuditEventToDB(ctx, "agent.device_key_bound", agentID, "success", "kind="+kind)
	c.JSON(http.StatusCreated, gin.H{"device_key_bound": true, "kind": kind})
}

// requireDeviceSignature checks a report's signature when the device has a
// key. It answers 401 and reports false when the report must be refused.
func (h *AgentAPIHandler) requireDeviceSignature(c *gin.Context, agentID string, body []byte) bool {
	if h.db == nil || h.db.Pool == nil {
		return true
	}
	ctx := c.Request.Context()
	pub, err := h.agentDeviceKey(ctx, agentID)
	if err != nil {
		h.logger.Error("device key lookup failed; refusing the report",
			logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read the device"})
		return false
	}
	if pub == nil {
		return true // no key on record: the token is the credential, as before
	}
	err = verifyAgentRequestSignature(pub, c.Request.Method, c.Request.URL.Path, agentID, body,
		c.GetHeader(headerAgentKeyTimestamp), c.GetHeader(headerAgentKeySignature), time.Now())
	if err == nil {
		return true
	}
	code := "device_signature_invalid"
	if errors.Is(err, errDeviceSignatureMissing) {
		code = "device_signature_required"
	}
	h.logAuditEvent("agent.report_refused", agentID, "denied", err.Error())
	h.logAuditEventToDB(ctx, "agent.report_refused", agentID, "denied", err.Error())
	c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error(), "code": code})
	return false
}
