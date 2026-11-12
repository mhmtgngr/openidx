# Inbound federation: signing in with Entra ID, AD FS and other OpenID Connect providers

OpenIDX is an OpenID Connect **relying party** for enterprise identity
providers. A user picks the provider on the login page (or is sent there by
home-realm discovery), signs in there, and comes back to OpenIDX, which then
issues its own tokens to the application that asked.

This guide covers Microsoft Entra ID, Active Directory Federation Services
(AD FS), Keycloak and any other OpenID Connect provider with a discovery
document. SAML identity providers are not supported as an upstream.

## How a sign-in flows

1. An application sends the browser to `/oauth/authorize`. With no session,
   OpenIDX stores the request under a `login_session` handle and shows the
   login page.
2. The user picks the provider, or types an email whose domain has a
   federation rule (`POST /api/v1/identity/federation/discover`). With
   `auto_redirect` the page goes straight to the provider and forwards the
   email as `login_hint`.
3. The login page calls `/oauth/authorize?idp_hint=<provider id>&login_session=<handle>`.
   OpenIDX completes the **stored** request: the application's `client_id`,
   `redirect_uri`, `state`, `nonce` and PKCE challenge come from the handle,
   never from that second URL.
4. OpenIDX reads the provider's discovery document and redirects with
   `state`, `nonce` and a PKCE challenge (S256). Only the parameters in the
   provider's `pass_through_params` (by default `login_hint`, `prompt`,
   `max_age`) are forwarded.
5. The provider returns to `<issuer>/oauth/callback`. OpenIDX exchanges the
   code, verifies the ID token (issuer, audience, signature, lifetime,
   nonce), maps the claims and resolves the user:
   1. by the provider link (`external_id_claim`, for example `oid`);
   2. by exact email, only when the provider marks the email verified or
      `jit_policy.link_by_email` is set;
   3. by creating the user, only when `jit_policy.provision` is on.
6. If the user still needs an OpenIDX second factor, the login page asks for
   it. Otherwise the application receives its authorization code.

When the sign-in is refused, the login page shows one of these reasons:

| `error=` | Meaning |
|---|---|
| `sso_idp_error` | The provider returned an error or no code |
| `sso_nonce_mismatch` | The ID token's nonce is not the one OpenIDX sent |
| `sso_user_not_found` | No linked or matching user, and provisioning is off |
| `sso_partner_not_registered` | An external person whose organization is not registered |
| `sso_sign_in_failed` | Discovery, token exchange or validation failed |

## Provider profile fields

Every provider on **Identity Providers** in the admin console carries a
federation profile. The quick-setup templates fill sensible values.

| Field | Default | Purpose |
|---|---|---|
| `issuer_url` | | The issuer exactly as the provider's ID tokens state it |
| `discovery_url` | `<issuer>/.well-known/openid-configuration` | Override when the document lives elsewhere |
| `use_pkce` | `true` | Send an S256 PKCE challenge upstream |
| `external_id_claim` | `sub` | The stable claim that links an account |
| `claims_mapping` | standard OIDC claims | OpenIDX field to upstream claim (`email`, `username`, `first_name`, `last_name`, `external_id`, `groups`, `roles`) |
| `group_mapping` | `[]` | `{"claim_value", "group_id"}` pairs. Only mapped groups are added or removed |
| `jit_policy` | `{"provision": false, "population": "internal"}` | Whether an unknown person is created, and as what |
| `trust_upstream_mfa` | `false` | Count the provider's MFA (`amr` such as `mfa`, `otp`, `hwk`) for internal users. External users always prove an OpenIDX factor |
| `pass_through_params` | `login_hint, prompt, max_age` | Authorization parameters forwarded upstream (`domain_hint`, `ui_locales`, `acr_values` may be added) |

## Microsoft Entra ID

1. In the Entra admin center, open **App registrations > New registration**.
   - Supported account types: *Accounts in this organizational directory only*.
   - Redirect URI: platform **Web**, value `<issuer>/oauth/callback`, where
     `<issuer>` is OpenIDX's `OAUTH_ISSUER` (for example
     `https://openidx.example.org/oauth/callback`).
2. Under **Certificates & secrets**, create a client secret and copy its value.
3. Under **Token configuration > Add optional claim > ID**, add `email` and
   `acct` (0 for members, 1 for guests). Add a **groups claim** if you map
   groups; choose *Security groups* and emit group object IDs.
4. Under **API permissions**, keep `openid`, `profile` and `email`
   (Microsoft Graph, delegated) and grant admin consent.
5. In OpenIDX, choose the **Microsoft Entra ID** template and set:
   - Issuer URL: `https://login.microsoftonline.com/<tenant-id>/v2.0`
   - Client ID: the application (client) ID; Client secret: the value from step 2.
   - External ID claim: `oid`. Entra's `sub` is pairwise per application,
     while `oid` is the user's object ID across the tenant.
6. Optional: to provision guests as external users, set `jit_policy` to, for
   example:

   ```json
   {"provision": true, "population": "internal",
    "population_rules": [{"claim": "acct", "values": ["1"], "population": "external"}]}
   ```

7. Turn on `trust_upstream_mfa` only after an Entra sign-in shows `mfa` in
   the `upstream_amr` field of the `sso_login` audit event.

## AD FS (Windows Server 2016 and later)

1. In AD FS Management, open **Application Groups > Add Application Group**
   and choose **Server application accessing a web API** (or *Server
   application* alone).
2. Redirect URI: `<issuer>/oauth/callback`. Copy the client identifier and
   generate a shared secret.
3. For the web API (if added), allow the `openid`, `profile`, `email` and
   `allatclaims` scopes, and add issuance transform rules that send `upn`,
   `email`, `given_name`, `family_name` and (for group mapping) `group`.
4. In OpenIDX, choose the **AD FS** template:
   - Issuer URL: `https://<adfs-host>/adfs`
   - Discovery URL: `https://<adfs-host>/adfs/.well-known/openid-configuration`
   - External ID claim: `sub` (AD FS's `sub` is stable per relying party).

## Keycloak and generic OpenID Connect

Create a confidential client with standard flow enabled and the redirect URI
`<issuer>/oauth/callback`. Use the realm URL
(`https://<host>/realms/<realm>`) as the issuer. Add a group membership
mapper with the claim name `groups` if you map groups.

## Network safety (SSRF)

Discovery, token and JWKS requests go through OpenIDX's outbound guard: each
host name is resolved once, every address must be public or listed in
`OIDX_OUTBOUND_ALLOWLIST`, and only `https` redirects are followed. An
on-premises provider on a private address (for example AD FS at
`10.0.0.5`) must be added to `OIDX_OUTBOUND_ALLOWLIST`.

`OIDCRP_ALLOW_LOOPBACK=1` additionally allows issuers on the loopback
interface. It exists for tests and single-host development. Leave it unset
in production.

## Paydaş kurumları (partner organizations)

A partner organization whose people already have accounts at their own
identity provider (a ministry's Entra tenant, a supplier's AD FS) does not
need one invitation per person. Its people sign in through that provider
and are provisioned as external users of the partner's vendor organization
on their first sign-in.

Set it up in **External users > Vendor organizations**:

1. Register the partner's provider under **Identity providers** as above.
2. Edit (or create) the vendor organization and set:
   - **How its people arrive**: `Federated (own IdP)`, or `Invitation and
     federated` to keep invitations working alongside.
   - **Identity provider**: the partner's provider. Leave it on "any
     provider" to match by the vendor's **allowed email domains** instead.
   - **Default sponsor**: required for a federated vendor. Every external
     account has a sponsor, and a person provisioned at sign-in has nobody
     else. **Change default sponsor** on the vendor row changes it later;
     accounts already provisioned keep their own sponsor.
   - **Default account lifetime** and **Sliding expiry**: with sliding
     expiry each successful sign-in moves the account end forward by the
     lifetime, never past the contract end or 365 days
     (`external.expiry_slid` in the audit trail).
   - **Default groups**: only groups open to external users are offered.
3. On the provider, `jit_policy.population_rules` can separate the
   partner's guests from your own staff on a shared tenant, for example
   `[{"claim": "acct", "values": ["1"], "population": "external"}]` with
   Entra's optional `acct` claim.

A person is matched to a vendor by the vendor's bound provider (and email
domain), then by allowed email domain, then by the provider's
`jit_policy.vendor_org_id`. A person who matches none is refused with
`sso_partner_not_registered`; a suspended vendor's people are refused. A
provisioned account starts as `pending_mfa` and enrols a strong factor
before it is used. **External users > Accounts > Source: Signed in through
their IdP** lists the accounts provisioned this way (`GET
/api/v1/identity/external-users?source=federated`).

Proxied applications: a route bound to an identity provider (`idp_id`)
signs in through OpenIDX's `/oauth/authorize?idp_hint=<idp_id>`, so the
same federation callback, provisioning and MFA rules apply. The access
proxy no longer talks to the provider itself.
