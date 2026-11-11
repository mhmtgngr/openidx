# Entra External MFA: OpenIDX as an Entra ID external authentication method

OpenIDX can be the second factor for people who sign in with Microsoft Entra ID.
Entra keeps the first factor and Conditional Access. When a policy asks for MFA,
Entra sends the person to OpenIDX, the person completes an OpenIDX factor (TOTP,
passkey or push), and OpenIDX returns a signed id_token that Entra accepts as
the MFA claim.

This runbook covers turning it on, registering it in Entra, piloting it with a
group, rotating keys and tracing a sign-in.

## How it works

| Endpoint | Purpose |
| --- | --- |
| `<issuer>/.well-known/openid-configuration` | Provider document Entra reads |
| `<issuer>/jwks` | Signing keys, each with an `x5c` certificate |
| `<issuer>/authorize` | Entra's request (`id_token_hint`, `form_post`) |

The issuer is `<OAUTH_ISSUER>/eam`. It is separate from the platform issuer, so
an id_token meant for Entra can never be used as a platform token. With
`EAM_ENABLED=false` (the default) every `/eam` endpoint answers 404.

OpenIDX checks each request: the `client_id` must be `EAM_CLIENT_ID`, the reply
address must be Entra's own (`https://login.microsoftonline.com/common/federation/externalauthprovider`),
the tenant must be on `EAM_TENANT_IDS`, and the `id_token_hint` must verify
against that tenant's published keys. The person is found by the hint's `oid`
(an Entra identity link or a directory sync), then by a verified email.
OpenIDX never creates a person because Entra asked for their second factor.

The id_token returned to Entra lives **five minutes** and carries
`acr=possessionorinherence` and an `amr` of `otp`, `fido` or `pop`.

## 1. Configure OpenIDX

Set these on the oauth-service and restart it:

| Variable | Value |
| --- | --- |
| `EAM_ENABLED` | `true` |
| `EAM_CLIENT_ID` | Application (client) ID of the app registration from step 2 |
| `EAM_TENANT_IDS` | Comma-separated Entra tenant IDs allowed to use it |
| `EAM_REQUIRE_STRONG_FACTORS` | `true` (default). `false` also allows SMS and email codes, which Entra will still be told were possession or inherence. The startup checklist flags it. |

The people who will use it must already exist in OpenIDX and have enrolled a
strong factor.

Open **Settings → Security → Entra External MFA** in the admin console (platform
administrators only). The card shows the issuer, discovery URL, JWKS URL,
authorization URL, client ID, the allowed tenants and the signing keys. Copy the
values from there. The first signing key is created on first use.

Make sure the discovery URL is reachable from the internet with a public TLS
certificate:

```bash
curl -s https://idp.example.com/eam/.well-known/openid-configuration | jq .issuer
curl -s https://idp.example.com/eam/jwks | jq '.keys[].kid'
```

## 2. Register an application in Entra

1. In the Entra admin center go to **App registrations → New registration**.
2. Name it (for example `OpenIDX MFA`). Choose single tenant or multitenant to
   match `EAM_TENANT_IDS`.
3. Add a **Web** redirect (reply) URL of `<issuer>/authorize`, for example
   `https://idp.example.com/eam/authorize`.
4. Copy the **Application (client) ID** into `EAM_CLIENT_ID`.
5. Grant **admin consent** for the application in every tenant that will use
   it (Enterprise applications → the app → Permissions → Grant admin consent).
   Without consent Entra cannot issue the `id_token_hint`.

## 3. Add the external authentication method, piloted with a group

Create the method with Microsoft Graph (or in the portal under
**Protection → Authentication methods → Add external method**). Target a
pilot group first:

```http
POST https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations
Content-Type: application/json

{
  "@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration",
  "displayName": "OpenIDX",
  "state": "enabled",
  "appId": "<EAM_CLIENT_ID>",
  "openIdConnectSetting": {
    "clientId": "<EAM_CLIENT_ID>",
    "discoveryUrl": "https://idp.example.com/eam/.well-known/openid-configuration"
  },
  "includeTargets": [
    { "targetType": "group", "id": "<pilot-group-object-id>" }
  ]
}
```

Widen `includeTargets` only after the pilot has run cleanly.

## 4. Require MFA with Conditional Access

Create (or reuse) a Conditional Access policy for the pilot group with
**Grant → Require multifactor authentication**. Entra offers OpenIDX among the
person's MFA methods. Use report-only mode first if the policy is new.

Test with a pilot account: sign in to `https://myapps.microsoft.com`, pick
OpenIDX, complete the factor and confirm Entra lets you in. The console card's
**Last 24 hours** count should go up by one.

## 5. Rotate the signing key

Entra caches the key set, so a new key must be published before it signs.
Click **Rotate key** on the console card, or:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://idp.example.com/api/v1/oauth/eam/keys/rotate
```

The new key appears in `/eam/jwks` at once and starts signing **two days**
later. The previous key stays published until its certificate expires, so
tokens already issued keep verifying. The card marks each key as signing,
published but not signing yet, or retired. Rotation is audited as
`eam.key_rotated`.

Rotate on a schedule (for example yearly) and after any suspected key
exposure. After an exposure, rotate and wait out the two days. There is no
instant cut-over because Entra would reject tokens signed by a key it has not
cached.

## 6. Trace a sign-in

Every attempt is audited with Entra's `client-request-id`:

| Action | Meaning |
| --- | --- |
| `eam.mfa_satisfied` | Factor completed, id_token returned to Entra |
| `eam.mfa_failed` | The person failed the factor |
| `eam.mfa_refused` | The request was refused (unknown tenant, bad hint, unknown person, wrong client) |

When a user reports a failed MFA prompt, take the **Correlation ID** or
**Request ID** from the Entra sign-in log entry and search the OpenIDX audit
log for it in the `client_request_id` detail. A `mfa_refused` event's reason
says which check failed.

The console card counts satisfied and refused or failed attempts over the last
24 hours. A rising refused count usually means a tenant missing from
`EAM_TENANT_IDS`, a mismatched `EAM_CLIENT_ID`, or people who exist in Entra but
not in OpenIDX.

## Turning it off

Remove the pilot group (or disable the method) in Entra first, so people are
not sent to a provider that answers 404. Then set `EAM_ENABLED=false`.
