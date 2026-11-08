// Package access — reading an RDP target's certificate for pinning.
//
// An entry in rdp_cert_mode 'pin' needs the fingerprint of the certificate
// its target presents, and an administrator has had no way to get it but to
// RDP there with another client and copy it out of a warning dialog. This
// reads it the way guacd would meet it: an X.224 connection request asking
// for TLS (or NLA, which runs over TLS), then a TLS handshake whose
// certificate is read and not trusted. Nothing is sent after the handshake:
// no credential, no CredSSP, and the connection is closed.
//
// Administrators only, against the entry's own stored target, so it dials
// nothing the broker would not. It answers what it found, including whether
// the access service's own trust store accepts the certificate for the
// entry's hostname, which is a guide to what 'verify' will do and not a
// promise: guacd checks against the trust store of the host it runs on.
package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// RDP negotiation (MS-RDPBCGR 2.2.1.1 and 2.2.1.2).
const (
	rdpNegReq        = 0x01
	rdpNegRsp        = 0x02
	rdpNegFailure    = 0x03
	rdpProtocolRDP   = 0x00
	rdpProtocolSSL   = 0x01
	rdpProtocolNLA   = 0x02
	rdpCertReadLimit = 10 * time.Second
)

// errRDPNoTLS is a target that offers only standard RDP security, so there is
// no certificate to read, and 'verify' and 'pin' sessions to it are refused.
var errRDPNoTLS = errors.New("the target offers only standard RDP security, with no TLS certificate; sessions in verify or pin mode are refused, and only ignore connects")

// rdpCertificate is what reading a target's certificate found.
type rdpCertificate struct {
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	DNSNames    []string  `json:"dns_names"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SelfSigned  bool      `json:"self_signed"`
	// Trusted: the access service's trust store accepts the certificate for
	// the entry's hostname. guacd checks against its own host's store.
	Trusted    bool   `json:"trusted"`
	TrustError string `json:"trust_error,omitempty"`
	Protocol   string `json:"protocol"`
}

// readRDPCertificate dials addr, negotiates TLS the way an RDP client does
// and returns the certificate the target presented. host is the name the
// certificate is checked against.
func readRDPCertificate(ctx context.Context, addr, host string) (*rdpCertificate, error) {
	ctx, cancel := context.WithTimeout(ctx, rdpCertReadLimit)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("could not reach the target: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// TPKT + X.224 Connection Request + RDP_NEG_REQ for TLS or NLA.
	req := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT, length 19
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR
		rdpNegReq, 0x00, 0x08, 0x00, rdpProtocolSSL | rdpProtocolNLA, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("could not negotiate with the target: %w", err)
	}
	selected, err := readRDPNegotiation(conn)
	if err != nil {
		return nil, err
	}
	if selected == rdpProtocolRDP {
		return nil, errRDPNoTLS
	}

	// Read, not trust: the point is to show what the target presents, and
	// nothing is sent over this connection after the handshake.
	tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS10}) //nolint:gosec // certificate is read for display, never trusted; nothing is sent after the handshake
	if err := tconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake with the target failed: %w", err)
	}
	defer tconn.Close()
	certs := tconn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("the target presented no certificate")
	}
	leaf := certs[0]
	sum := sha256.Sum256(leaf.Raw)
	hexed := hex.EncodeToString(sum[:])
	pairs := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		pairs = append(pairs, hexed[i:i+2])
	}
	out := &rdpCertificate{
		Fingerprint: "sha256:" + strings.Join(pairs, ":"),
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		DNSNames:    append([]string{}, leaf.DNSNames...),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		// CheckSignatureFrom would demand a CA certificate; RDP's own are not.
		SelfSigned: bytes.Equal(leaf.RawSubject, leaf.RawIssuer) &&
			leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil,
		Protocol: map[uint32]string{rdpProtocolSSL: "tls", rdpProtocolNLA: "nla"}[selected],
	}
	if out.Protocol == "" {
		out.Protocol = "tls"
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); verr != nil {
		out.TrustError = verr.Error()
	} else {
		out.Trusted = true
	}
	return out, nil
}

// readRDPNegotiation reads the X.224 Connection Confirm and returns the
// protocol the target selected.
func readRDPNegotiation(r io.Reader) (uint32, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, fmt.Errorf("the target closed the connection during negotiation: %w", err)
	}
	if hdr[0] != 0x03 {
		return 0, errors.New("the target did not answer as an RDP server")
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4]))
	if n < 11 || n > 512 {
		return 0, errors.New("the target sent a malformed RDP negotiation")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, fmt.Errorf("the target closed the connection during negotiation: %w", err)
	}
	// body: X.224 CC (7 bytes) then, optionally, the 8-byte negotiation.
	if len(body) < 7+8 {
		// No negotiation response: an old server speaking standard RDP only.
		return rdpProtocolRDP, nil
	}
	neg := body[7:]
	switch neg[0] {
	case rdpNegRsp:
		return binary.LittleEndian.Uint32(neg[4:8]), nil
	case rdpNegFailure:
		// SSL_NOT_ALLOWED_BY_SERVER (2) and the like: the server wants
		// standard RDP security.
		return rdpProtocolRDP, nil
	default:
		return 0, errors.New("the target sent a malformed RDP negotiation")
	}
}

// handlePamReadRDPCertificate — POST /pam/entries/:id/rdp-certificate (admin).
// Reads the certificate the entry's target presents, for the administrator to
// compare and pin. Audited as pam.entry_certificate_read.
func (s *Service) handlePamReadRDPCertificate(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	entryID := c.Param("id")
	var entryType, hostname, reach string
	var port int
	err = s.db.Pool.QueryRow(ctx, `SELECT entry_type, COALESCE(hostname,''), COALESCE(port,0), reach_mode
		  FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, org.ID).Scan(&entryType, &hostname, &port, &reach)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamReadRDPCertificate: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		return
	}
	if pamEntryTypeByName[entryType].Protocol != "rdp" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only an RDP entry has a certificate to read"})
		return
	}
	if reach == "ziti" {
		// The target is reached over the overlay, which this service does not
		// dial; reading it directly could show a different host's certificate.
		c.JSON(http.StatusConflict, gin.H{"error": "the certificate of an OpenZiti-reach entry cannot be read from here; read it on the target and enter its SHA-256 fingerprint",
			"code": "rdp_certificate_overlay"})
		return
	}
	if hostname == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the entry has no hostname"})
		return
	}
	if port == 0 {
		port = 3389
	}
	cert, rerr := readRDPCertificate(ctx, net.JoinHostPort(hostname, strconv.Itoa(port)), hostname)
	audit := map[string]interface{}{"entry_id": entryID, "target": logsafe.Clean(hostname), "port": port}
	if rerr != nil {
		audit["error"] = rerr.Error()
		s.logAuditEvent(c, "pam.entry_certificate_read", entryID, "pam_entry", audit)
		code := "rdp_certificate_unreadable"
		if errors.Is(rerr, errRDPNoTLS) {
			code = "rdp_no_tls"
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": rerr.Error(), "code": code})
		return
	}
	audit["fingerprint"], audit["trusted"] = cert.Fingerprint, cert.Trusted
	s.logAuditEvent(c, "pam.entry_certificate_read", entryID, "pam_entry", audit)
	c.JSON(http.StatusOK, gin.H{"certificate": cert})
}
