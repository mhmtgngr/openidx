# SAML 2.0 Identity Provider - OpenIDX

OpenIDX is a SAML 2.0 identity provider. The oauth-service publishes IdP
metadata, answers AuthnRequests from registered service providers, starts
unsolicited (IdP-initiated) sign-on, and takes part in Single Logout in both
directions.

OpenIDX is not a SAML service provider. It does not consume assertions from
another identity provider, so there is no assertion consumer service in
OpenIDX to test with forged assertions. The negative assertion tests below run
against the two external service providers instead, and the Go tests cover the
SAML messages OpenIDX does receive: AuthnRequests and LogoutRequests.

## Endpoints

| Endpoint | Binding | Purpose |
| --- | --- | --- |
| `GET /saml/idp/metadata` | | IdP metadata: entity ID, signing certificate, SSO and SLO endpoints |
| `GET /saml/idp/sso`, `POST /saml/idp/sso` | HTTP-Redirect, HTTP-POST | SP-initiated sign-on (AuthnRequest in, Response out over HTTP-POST) |
| `GET /saml/idp/sso/unsolicited?sp_entity_id=<id>&RelayState=<state>` | | IdP-initiated sign-on to a registered service provider |
| `GET /saml/idp/slo`, `POST /saml/idp/slo` | HTTP-Redirect, HTTP-POST | Single Logout: a LogoutRequest from an SP, or a request from the signed-in user to log out everywhere |
| `/api/v1/saml/service-providers` | | Management API: register, update, import metadata, rotate certificates |

The code is in `internal/oauth/saml.go`, `internal/oauth/saml_slo.go`,
`internal/oauth/saml_sp.go` and `internal/oauth/saml_metadata.go`.

## What the IdP sends

Every Response is signed, and so is the assertion inside it. The assertion is
signed first. If the service provider asked for encryption, the signed
assertion is then encrypted. The Response around it is signed last, so the
Response signature covers the bytes that are sent, including the ciphertext.
SAML2Int requires the Response signature (\[SDP-IDP30\]). Service providers that
check only the assertion signature find it there too. A Response is never
built without a signature.

| Property | Value |
| --- | --- |
| Signature | enveloped XML Signature, RSA-SHA256, SHA-256 digest, exclusive canonicalization |
| Signing key | the active key in the signing-key store; its certificate is in the metadata |
| Assertion encryption | AES-256-GCM (`http://www.w3.org/2009/xmlenc11#aes256-gcm`), key transport RSA-OAEP (`http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`), `EncryptedKey` inside the `EncryptedData` `KeyInfo` |
| Response binding | HTTP-POST to the ACS URL registered for the service provider |
| LogoutResponse | HTTP-Redirect, signed over the query string (SAML Bindings 3.4.4.1) |
| LogoutRequest to an SP | sent over the back channel to the SP's HTTP-Redirect SLO URL, signed over the query string |

The signing library is `github.com/russellhaering/goxmldsig` on
`github.com/beevik/etree`. Encryption uses the Go standard library.

If a service provider has `encryption_enabled` set and OpenIDX cannot encrypt
to it (no usable RSA certificate), sign-on fails with an error. OpenIDX does
not send that SP a plaintext assertion instead.

## What the IdP accepts

### AuthnRequest

A request is refused (400 or 403) when:

- its issuer is not a registered service provider, or the service provider is
  disabled;
- it names an AssertionConsumerServiceURL the service provider did not
  register;
- it carries a signature that does not verify against the service provider's
  registered certificate. This applies to both the query-string signature of
  the HTTP-Redirect binding and an enveloped signature in the XML. A bad
  signature is refused even when signing is optional;
- the service provider must sign its requests and the request is unsigned;
- the signature algorithm is not RSA-SHA1, RSA-SHA256, RSA-SHA384 or
  RSA-SHA512.

A service provider must sign its AuthnRequests when
`require_signed_authn_requests` is set. Importing metadata that says
`AuthnRequestsSigned="true"` sets it. Importing metadata never clears it.

### LogoutRequest

SAML Profiles 4.4.4.1 requires a LogoutRequest to be authenticated. Over the
browser bindings that means a signature, so OpenIDX refuses a LogoutRequest
unless all of the following hold:

- it is signed by the service provider it names;
- its `Destination` is this IdP's SLO endpoint;
- it was issued no more than five minutes ago, is not dated in the future
  (three minutes of clock skew are allowed), and is not past its own
  `NotOnOrAfter`;
- its ID has not been processed before. The record of processed IDs is kept in
  Redis. If Redis is unavailable, the request is refused.

A LogoutRequest ends only sessions that OpenIDX recorded for that service
provider when it issued the assertion, matched by SessionIndex or NameID.

## Registering a service provider

The fields that control signing and encryption are:

| Field | Meaning |
| --- | --- |
| `certificate` | The service provider's signing certificate. OpenIDX verifies AuthnRequests and LogoutRequests against it. |
| `encryption_certificate` | The certificate to encrypt assertions to. If it is empty, `certificate` is used. |
| `encryption_enabled` | Encrypt assertions to this service provider. |
| `require_signed_authn_requests` | Refuse unsigned AuthnRequests from this service provider. |

`POST /api/v1/saml/service-providers/import-metadata` reads these fields from
the SP's metadata. It reads the signing and encryption `KeyDescriptor`s, the
HTTP-POST ACS URL, the HTTP-Redirect SLO URL, and `AuthnRequestsSigned`.
Migration 204 (`internal/migrations/sql_v204.go`) adds `encryption_certificate`
and `require_signed_authn_requests`.

## Interoperability testing

The interop suite runs OpenIDX against two service providers that do not use
OpenIDX's SAML code. A service provider built on goxmldsig would accept the
same mistakes OpenIDX makes, so neither service provider uses it.

| Service provider | Version | SAML and XML security stack |
| --- | --- | --- |
| SimpleSAMLphp | 2.5.3.1 (release tarball, SHA-256 checked) | PHP: simplesamlphp/saml2, xmlseclibs |
| Keycloak, as an identity-brokering SP | 26.7.4 (official image, pinned by digest) | Java: Keycloak SAML core on Apache Santuario |

The workflow is `.github/workflows/saml-interop.yml`, and the suite is
`test/interop/saml/`. The suite uses the `samlinterop` build tag. The
workflow runs on changes to the SAML code, and on demand.

### Profiles

Each service provider runs twice, once in each profile:

1. **Signed assertion in a signed Response.** The SP signs its AuthnRequests
   and requires them signed in OpenIDX (`require_signed_authn_requests`). It
   requires a signed Response (SimpleSAMLphp) or a signed assertion (Keycloak)
   and validates the signature against the certificate in the OpenIDX metadata.
2. **Encrypted assertion in a signed Response.** The same, plus the SP
   publishes an encryption key, requires encrypted assertions, and the test
   checks that an `EncryptedAssertion` arrived.

### Flows

| Flow | SimpleSAMLphp | Keycloak |
| --- | --- | --- |
| SP-initiated SSO (signed AuthnRequest over HTTP-Redirect, Response over HTTP-POST) | yes | yes (OIDC login with `kc_idp_hint`, brokered to OpenIDX) |
| IdP-initiated SSO (`/saml/idp/sso/unsolicited`) | yes | yes (to the broker's `/endpoint/clients/<name>` URL) |
| SP-initiated SLO (signed LogoutRequest, signed LogoutResponse) | yes | yes |
| IdP-initiated SLO (signed LogoutRequest over the back channel) | yes | yes |

For each flow, the suite checks the resulting session on both sides. The
identity at the SP must be the user OpenIDX asserted, with the same NameID and
attributes. After logout, neither the IdP session nor the SP session may
remain.

### Negative controls

A test in which the SP accepts everything would pass without testing anything.
So the suite also sends each SP forged Responses and requires the SP to refuse
every one:

| Forgery | SimpleSAMLphp | Keycloak |
| --- | --- | --- |
| signatures removed | refused | refused |
| signed by a key the SP does not trust | refused | refused |
| audience is another SP, re-signed with the IdP key | refused | refused |
| expired, re-signed with the IdP key | refused | refused |
| a genuine Response replayed | refused | not tested |

Before the forgeries, the SP must accept a genuine Response. Otherwise a
refusal would prove nothing.

Replay is a property of the SP, not of the IdP; the SimpleSAMLphp run
covers it, and the Keycloak run has no replay case.

### Go tests run by the unit matrix

These tests run against the real routes and a migrated PostgreSQL. They are in
`internal/oauth/saml_idp_protocol_testdb_test.go`:

- `TestSAMLIdPRefusesAuthnRequestsItMustNotAnswer`: an unknown or disabled
  SP, an unregistered ACS URL, an unsigned request where signing is required
  (both bindings), a wrong key (both bindings), a request altered after
  signing (both bindings), a bad signature where signing is optional, and an
  unsupported SigAlg. It also checks that valid requests are answered.
- `TestSAMLIdPResponsesAreSignedAndEncryptedAsRegistered`: decrypts the
  assertion and verifies both signatures and their placement. It checks that
  the assertion is well-formed when read on its own. It checks that encryption
  that cannot be done fails, and that no Response is built unsigned.
- `TestSAMLIdPInitiatedSSO`: unsolicited sign-on and its refusals.
- `TestSAMLIdPRefusesLogoutRequestsItCannotTrust`: unsigned (both bindings),
  wrong key, wrong Destination, too old, past NotOnOrAfter, dated in the
  future, unknown SP, and replayed LogoutRequests are refused. A valid
  LogoutRequest ends the session and is answered with a signed LogoutResponse.
- `TestParseServiceProviderMetadataFromIndependentSPs`: reads SimpleSAMLphp
  and Keycloak metadata as they publish it.

## Known limits

- OpenIDX signs with RSA keys only, and encrypts only to RSA certificates.
- The Response is always sent over HTTP-POST. HTTP-Artifact is not supported.
- OpenIDX sends LogoutRequests and LogoutResponses only over the
  HTTP-Redirect binding. When metadata lists no HTTP-Redirect SLO endpoint,
  OpenIDX uses the first SLO endpoint listed, and a service provider that
  accepts only HTTP-POST there will not understand the message.
- The admin console does not yet show `encryption_certificate` or
  `require_signed_authn_requests`. Set them through the management API or by
  importing metadata.
