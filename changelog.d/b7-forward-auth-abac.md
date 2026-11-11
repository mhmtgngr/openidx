### Security
- **Forward-auth now applies ABAC policies.** Routes fronted by the edge's
  forward-auth (`/access/.auth/decide`) are judged by the tenant's attribute
  policies exactly like the proxy, staged by `ABAC_ENFORCE=off|observe|enforce`.
