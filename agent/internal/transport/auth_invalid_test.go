package transport

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTheServersRefusalsAreTold: 403 is a revoke, 401 a refused credential,
// and anything else an ordinary failure. Each is a different thing to show
// the person at the device, so the client must not fold them together.
func TestTheServersRefusalsAreTold(t *testing.T) {
	for _, tc := range []struct {
		status        int
		revoked, auth bool
	}{
		{http.StatusForbidden, true, false},
		{http.StatusUnauthorized, false, true},
		{http.StatusBadGateway, false, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		}))
		c := NewClient(srv.URL, "tok", "a1")

		_, err := c.GetConfig()
		require.Error(t, err)
		require.Equal(t, tc.revoked, errors.Is(err, ErrAgentRevoked), "config %d: revoked", tc.status)
		require.Equal(t, tc.auth, errors.Is(err, ErrAgentAuthInvalid), "config %d: credential refused", tc.status)

		_, err = c.ReportResultsResponse([]byte(`{}`))
		require.Error(t, err)
		require.Equal(t, tc.auth, errors.Is(err, ErrAgentAuthInvalid), "report %d: credential refused", tc.status)
		srv.Close()
	}
}

// TestARefusedCredentialIsNotAnOverlayFailure: the resilient transport falls
// back to HTTPS only when the overlay is unreachable. A 401 is the server's
// answer and must surface, not trip the fallback.
func TestARefusedCredentialIsNotAnOverlayFailure(t *testing.T) {
	require.False(t, isOverlayUnreachable(ErrAgentAuthInvalid))
	require.False(t, isOverlayUnreachable(errors.New("report request: "+ErrAgentAuthInvalid.Error())))
}
