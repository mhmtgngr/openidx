# Edge provider modules — one interface, three providers

Global-scale plan task 1.1 (`docs/archive/2026-09-13-global-scale-cell-architecture-plan.md`),
design ADR-3: L3/L4 and volumetric L7 DDoS is **bought** from an anycast edge, never
built. The provider is decision **K1** in the roadmap; until it is taken, all three
modules exist so the choice costs a `module "edge" { source = ... }` line and not a
rewrite.

## The shared contract

| Input | Meaning |
|---|---|
| `name` | Prefix for every provider resource |
| `zone_domain` | The public apex the tenant subdomains hang off (`TENANT_BASE_DOMAIN`) |
| `edge_hostnames` | Public names the edge answers for (`auth.`, `api.`, `*.` wildcard where the provider allows) |
| `origin_hostname` | The **cloaked** origin (the cell's NLB/ingress). Never published in public DNS |
| `rules_file` | Defaults to `../edge-common/rules.json` — the §5.3 table as data |
| `tags` | Provider tags/labels |

| Output | Meaning |
|---|---|
| `edge_cidrs` | The provider's published source ranges. Feed them to `OIDX_EDGE_TRUSTED_CIDRS` / `EDGE_TRUSTED_CIDRS` and to the origin's security group; the `edge-cidr-sync` job keeps them current |
| `origin_verification` | How the origin proves a request came through the edge: mTLS CA (Cloudflare), a secret header (CloudFront), the `X-Azure-FDID` value (Front Door). **Enforce it at the origin** — an IP allow-list alone is not cloaking |
| `edge_hostname` | The provider hostname to CNAME the public names to |

## What each module renders from `rules.json`

| Rule | Cloudflare | AWS | Azure |
|---|---|---|---|
| `rate_rules` (per source, per minute) | `http_ratelimit` ruleset | WAFv2 rate-based rules, 60 s window | Front Door WAF `RateLimitRule` custom rules |
| `cache_rules` | `http_request_cache_settings` ruleset | CloudFront cache policies + ordered behaviours | Front Door rule set `route_configuration_override_action` |
| `limits` (body/url/header) | WAF managed ruleset + custom size rule | WAFv2 `size_constraint_statement` rules | Front Door WAF `SizeRule` custom rules |
| Managed WAF | Cloudflare Managed Ruleset | AWS Common, Known Bad Inputs, IP Reputation | Microsoft_DefaultRuleSet 2.1 + Bot Manager 1.0 |
| Origin cloaking | Authenticated Origin Pulls (mTLS) | Custom origin header (secret) | `X-Azure-FDID` header |

Things the edge does **not** know and therefore does not enforce: tenant, user,
client_id, request cost. Those budgets live in APISIX (`limit-count` per tenant host)
and the Go admission layer (plan task 3.5).

## Validation

Each module declares its own `required_providers`, so it validates standalone:

```bash
cd deployments/terraform/modules/edge-cloudflare   # or edge-aws, edge-azure
terraform init -backend=false && terraform validate
```

CI runs this for all three (`.github/workflows/terraform.yml`).
