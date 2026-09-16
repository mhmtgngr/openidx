// Package cell is the backstop for a request that reached the wrong cell.
//
// WHAT THIS IS NOT. It is not routing. In the cell model the edge decides which
// cell serves a tenant, from the tenant directory, and sends the request there;
// that is a lookup and a cache, and it lives at the edge. This package is what
// happens when that lookup was wrong or stale -- the request arrives at a cell
// whose database does not hold this tenant, and the honest answer is to say so
// rather than to serve a confident 404 from a cell that simply does not have
// the data. RFC 9110's 421 Misdirected Request is exactly that answer, and
// X-OpenIDX-Cell names who should have served it.
//
// The two halves are easy to conflate and must not be: the directory makes the
// common case right, and this makes the uncommon case legible. Neither
// substitutes for the other.
package cell

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Claim is the JWT claim naming the cell that minted a token.
const Claim = "cell"

// Header tells the caller which cell answered, on every misdirected response.
// A client that can read it can correct its own routing without a directory
// lookup, and an operator reading a log can tell a misrouted request from a
// genuinely missing tenant -- which look identical without it.
const Header = "X-OpenIDX-Cell"

// Misdirected reports whether a token minted in tokenCell was presented to a
// process serving cell `serving`.
//
// TWO CASES ANSWER "NO" AND BOTH ARE DELIBERATE.
//
// An empty `serving` is an install that is not celled at all, which is every
// install today. Nothing about single-cell deployment changes because this
// package exists: with no CELL_ID there is no cell to be wrong about.
//
// An empty tokenCell is a token minted before this claim existed, or by an
// issuer that is not celled. Refusing those would make the rollout a flag day:
// every token outstanding at the moment an operator sets CELL_ID would start
// failing, including the ones minted seconds earlier by the same process. The
// claim has to be present in a token before it can be required of one, and the
// gap between those two is a token lifetime. So an unmarked token is served,
// and the cost is written here rather than discovered: during that window a
// genuinely misrouted request with an old token gets the 404 it would have got
// anyway, not a 421.
func Misdirected(tokenCell, serving string) bool {
	if serving == "" || tokenCell == "" {
		return false
	}
	return tokenCell != serving
}

// Guard refuses a request whose token names a different cell.
//
// It runs AFTER authentication, because the claim it reads is only worth
// anything once the signature over it has been checked -- an unverified cell
// claim is a header the caller chose. It reads the value the auth middleware
// bound (middleware.BindSubjectClaims), for the same reason the roles and
// groups claims are read from there: one place, and a census that fails the
// build when an auth middleware does not bind the subject.
//
// serving empty disables it entirely, which is the default.
func Guard(serving string, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if serving == "" {
			c.Next()
			return
		}
		tokenCell, _ := c.Get(Claim)
		asString, _ := tokenCell.(string)
		if !Misdirected(asString, serving) {
			c.Next()
			return
		}

		// The header goes on the refusal AND is the point of it: a 421 without
		// it tells the caller it guessed wrong and nothing about what would be
		// right, which leaves retrying as the only move.
		c.Header(Header, serving)
		if logger != nil {
			logger.Warn("request carried a token minted in another cell",
				zap.String("token_cell", asString),
				zap.String("serving_cell", serving),
				zap.String("path", c.Request.URL.Path))
		}
		c.AbortWithStatusJSON(http.StatusMisdirectedRequest, gin.H{
			"error":             "misdirected_request",
			"error_description": "this token belongs to another cell; retry against the cell named in " + Header,
			"cell":              serving,
		})
	}
}
