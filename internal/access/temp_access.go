// Temporary access links, retired (Phase 3, D2).
//
// A temporary access link was an anonymous URL that put whoever held it onto
// a PAM entry's session: no identity, no second factor, no sponsor, nothing
// but the token. The vendor framework replaced it -- a vendor's people are
// external users with their own factor, reaching only what a running
// engagement covers, approved by and visible to their sponsor -- so the link
// is no longer issued and no longer redeems. v1.44.0 kept the issued links as
// read-only history; migration 236 dropped the tables and the history routes
// went with them. What is left is the page a link opened now gets, which says
// how access works instead and reads nothing.
package access

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

// handleRetiredTempAccess — GET /temp-access/:token. Links no longer redeem.
// The page is the same for every token and reads nothing: whether a token was
// ever issued is not the visitor's to learn, and since migration 236 there is
// nothing left to read.
func (s *Service) handleRetiredTempAccess(c *gin.Context) {
	renderTempAccessError(c, http.StatusGone, "Temporary Access Links Are Retired",
		"This kind of link no longer opens a session. Ask the person who sent it for access as a "+
			"vendor user: you sign in with your own account, and you reach what your engagement covers.")
}

// renderTempAccessError writes a plain page directly rather than through
// c.HTML: nothing in this repository registers a template renderer, so c.HTML
// would dereference a nil renderer and panic. Both values are escaped.
func renderTempAccessError(c *gin.Context, status int, title, message string) {
	page := fmt.Sprintf(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
 body{font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1f2933;
      background:#f5f7fa;margin:0;display:flex;min-height:100vh;
      align-items:center;justify-content:center;padding:24px}
 main{background:#fff;border:1px solid #d9e2ec;border-radius:12px;
      padding:32px;max-width:34rem}
 h1{font-size:1.25rem;margin:0 0 12px}
 p{margin:0;color:#3e4c59}
</style></head>
<body><main><h1>%s</h1><p>%s</p></main></body></html>
`, template.HTMLEscapeString(title), template.HTMLEscapeString(title),
		template.HTMLEscapeString(message))
	c.Data(status, "text/html; charset=utf-8", []byte(page))
}
