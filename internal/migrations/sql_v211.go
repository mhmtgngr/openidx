package migrations

// Migration v211 -- proxy_routes.host: the host a route is served on, held by
// at most one enabled route in the whole installation.
//
// The access proxy and forward-auth find the route for a request by the host
// the browser addressed, before any organization is known: the host is what
// decides the organization. That lookup was `from_url LIKE '%' || host || '%'`
// over every organization's routes, highest priority first, and nothing kept
// two organizations off the same host, because the route API accepted any
// from_url. So an administrator of one organization could create a route on
// another organization's host with a higher priority and receive that host's
// traffic at an upstream of their choosing: its users' requests, the sign-ins
// made on it and the identity headers the proxy adds. The substring match
// widened it, since a from_url of https://attacker.example/?victim.example
// matched requests for victim.example. The BrowZer configuration and the edge
// routes were rendered from the same rows, so the host went with them.
//
// host is from_url's host, lowercased, without userinfo, port, IPv6 brackets
// or a trailing dot, computed by proxy_route_host() as a generated column, so
// every writer (the route API, quick create, bulk import, app publishing, Ziti
// discovery, the BrowZer handlers and the BrowZer domain change) stores it
// without computing it. It is NULL where from_url names no host the proxy
// could serve: a path such as /service-name, an empty from_url, or a scheme
// other than http and https (tcp://, ssh://). A from_url without a scheme,
// app.example.com[:port][/path], names its host, as the BrowZer generator has
// always read it. Lookups compare host with proxy_route_host() of the
// request's Host header, so one function decides both sides.
//
// ONE ENABLED ROUTE PER HOST. The unique index is over enabled routes, so an
// enabled route holds its host for the whole installation. That is what makes
// it cross-organization, and it also allows one enabled route per host within
// an organization, which is how the data plane has always behaved: the proxy
// served the highest-priority route for a host whatever its path, the BrowZer
// generator collapsed same-host routes to one, the edge rendered them onto one
// host, and the Relations & Integrity Doctor's host-unique check reported a
// second one as an error. A disabled route keeps its host and may share it;
// enabling it claims the host.
//
// EXISTING DUPLICATES. For each host with more than one enabled route, the
// organization whose enabled route on that host was created first keeps it,
// and of that organization's routes the one the proxy served keeps it: the
// highest priority, then the oldest. Every other enabled route on the host is
// disabled, not deleted, and its updated_at set. The first claimant rather
// than the highest priority, because priority is exactly what a takeover sets.
// The routes this disabled are the disabled routes whose host an enabled route
// holds:
//
//	SELECT d.org_id, d.id, d.name, d.from_url, e.org_id AS held_by
//	  FROM proxy_routes d JOIN proxy_routes e ON e.host = d.host AND e.enabled
//	 WHERE NOT d.enabled;
//
// Down drops the index, the column and the function. The routes Up disabled
// stay disabled: enabling them again would give the host back to whoever took
// it.

var proxyRouteHostUp = `-- Migration 211: the host a proxy route is served on, held by one enabled route.
CREATE OR REPLACE FUNCTION proxy_route_host(url TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS
$$
SELECT NULLIF(rtrim(lower(btrim(substring(
    CASE
        WHEN url ~* '^https?://' THEN substring(url FROM '^[A-Za-z]+://(.*)$')
        WHEN url ~ '^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?([/?#]|$)' THEN url
    END
    FROM '^(?:[^/?#]*@)?(\[[^]/?#@]*\]|[^/?#:@]*)'), '[]')), '.'), '')
$$;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS host TEXT GENERATED ALWAYS AS (proxy_route_host(from_url)) STORED;
UPDATE proxy_routes r SET enabled = false, updated_at = NOW()
  FROM (
    SELECT id, row_number() OVER (
             PARTITION BY host
             ORDER BY first_in_org ASC NULLS LAST, org_id, priority DESC NULLS LAST, created_at ASC NULLS LAST, id
           ) AS claim
      FROM (
        SELECT id, host, org_id, priority, created_at,
               min(created_at) OVER (PARTITION BY host, org_id) AS first_in_org
          FROM proxy_routes
         WHERE enabled AND host IS NOT NULL
      ) enabled_routes
  ) claims
 WHERE r.id = claims.id AND claims.claim > 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_routes_enabled_host ON proxy_routes (host) WHERE enabled;
`

var proxyRouteHostDown = `-- Migration 211 down: drop the host column, its index and its function.
DROP INDEX IF EXISTS idx_proxy_routes_enabled_host;
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS host;
DROP FUNCTION IF EXISTS proxy_route_host(TEXT);
`
