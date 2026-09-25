package oauth

import "github.com/gin-gonic/gin"

// noStore marks every response of the route it guards as one that no cache may
// keep, whatever the handler goes on to answer.
//
// RFC 6749 §5.1: the authorization server MUST send "Cache-Control: no-store"
// and "Pragma: no-cache" in any response that contains tokens, credentials or
// other sensitive information. The token endpoint sent neither, so a shared
// cache or a browser back/forward cache was free to keep an access, refresh or
// ID token (the conformance suite's oidcc-refresh-token module flags exactly
// this).
//
// It is a middleware on the route, not a line in each handler, because the
// token endpoint alone has five grants and a dozen error returns, and "every
// response" is only true if no return path can be written without it. Errors
// are covered as well: RFC 6749 §5.2 error bodies come from the same endpoint,
// and the headers cost nothing there.
//
// Pragma is HTTP/1.0 and ignored by modern caches, but the RFC names it and a
// relying party's conformance check reads it.
func noStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Next()
}
