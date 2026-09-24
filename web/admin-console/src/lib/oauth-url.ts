// Where the console sends OAuth requests (/oauth/token, /oauth/authorize,
// /oauth/logout, ...). The OAuth service answers on the API's origin in every
// documented deployment: the edge routes /oauth there, and so does the Vite dev
// proxy. So an unset VITE_OAUTH_URL falls back to the API URL, and then to the
// page's own origin. A fixed host here would only ever work on the one machine
// that runs it.
export function resolveOAuthURL(): string {
  return (
    import.meta.env.VITE_OAUTH_URL ||
    import.meta.env.VITE_API_URL ||
    import.meta.env.VITE_API_BASE_URL ||
    window.location.origin
  )
}
