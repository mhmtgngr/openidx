package migrations

// Migration v204 -- saml_sp_signing_and_encryption: two per-service-provider
// settings the SAML IdP needs to honour what a service provider's metadata
// says about signatures and encryption.
//
// encryption_certificate is the service provider's ENCRYPTION certificate:
// the KeyDescriptor with use="encryption" in its metadata. The IdP encrypts
// assertions to it when encryption_enabled is set. certificate stays what it
// is, the signing certificate the IdP verifies the service provider's
// requests against. Many service providers publish one certificate for both
// uses, and some (Keycloak brokering, among others) publish two, so a single
// column cannot serve both. NULL means "use certificate", which is what a
// service provider with one key pair expects.
//
// require_signed_authn_requests makes the IdP refuse an AuthnRequest from
// this service provider unless it carries a signature that verifies against
// certificate. It is set from AuthnRequestsSigned="true" in the service
// provider's metadata, and an administrator can set it directly. It defaults
// to false, which is what every existing registration does today: a signature
// that is present is verified, and a request without one is accepted.
//
// Down drops both columns. An install rolling back to v203 is one where the
// IdP encrypts to certificate and never requires a signature, which is where
// it already was.

var samlSPSigningAndEncryptionUp = `-- Migration 204: per-SP encryption certificate and signed-AuthnRequest requirement.
ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS encryption_certificate TEXT;
ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS require_signed_authn_requests BOOLEAN NOT NULL DEFAULT false;
`

var samlSPSigningAndEncryptionDown = `-- Migration 204 down: drop the per-SP encryption certificate and signing requirement.
ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS require_signed_authn_requests;
ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS encryption_certificate;
`
