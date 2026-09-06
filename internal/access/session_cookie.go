package access

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/config"
)

// sessionCookieSecure decides the Secure flag for `_openidx_proxy_session`,
// the cookie that carries a ZTNA proxy session.
//
// The three call sites used to pass `config.IsProduction()` directly, which is
// wrong in one direction that matters: an install whose APP_ENV is anything
// other than "production"/"prod" — "staging", "uat", a customer's own label —
// but which terminates TLS at an ingress still shipped the session cookie
// without Secure, so a single plain-HTTP request to the same host would leak
// it. Environment names are documentation; the transport the request actually
// arrived on is the fact.
//
// So: Secure when the request reached us over TLS (terminated here, or at a
// hop that said so), OR when the process is configured as production — the
// last clause keeps a production install behind a proxy that forwards no
// X-Forwarded-Proto exactly as protected as it was before this function
// existed. The result is never weaker than the old predicate and is stronger
// wherever TLS is real but the environment label is not "production".
//
// Trusting X-Forwarded-Proto here needs no trusted-proxy list, because the
// header can only ever turn the flag ON: a forged `https` makes the browser
// refuse to send the cookie over plain HTTP, which is a restriction, not a
// bypass. Forcing it OFF requires stripping the header from a request that
// genuinely arrived over TLS — which is an attacker who already sits on the
// connection, and a plain-HTTP request needs no Secure flag to begin with.
func sessionCookieSecure(c *gin.Context, cfg *config.Config) bool {
	if c != nil && c.Request != nil {
		if c.Request.TLS != nil {
			return true
		}
		// A comma-separated list is legal; the first hop is the client's.
		proto, _, _ := strings.Cut(c.GetHeader("X-Forwarded-Proto"), ",")
		if strings.EqualFold(strings.TrimSpace(proto), "https") {
			return true
		}
	}
	return cfg != nil && cfg.IsProduction()
}
