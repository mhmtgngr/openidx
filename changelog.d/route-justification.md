### Added
- **Ask why before a proxied application opens.** A route can require a
  reason (Proxy Routes → Ask why before opening). After the access decision
  admits a person, their first page load in a browser session goes to a
  short form on the application's host; the reason is audited as
  `proxy.access_justified` before anything is forwarded, and holds for that
  session for the route's time. API and bearer callers on such a route get
  403 `justification_required`. Migration 244. The APISIX forward-auth hook
  now passes the caller's `Accept` header so it can tell a page load from an
  API call.
