// Quick-setup templates for the identity providers page. An enterprise
// template also carries the federation profile the provider needs
// (internal/identity/federation_profile.go); fields a template leaves out take
// the server defaults (use_pkce on, external_id_claim "sub", JIT off).
export interface ProviderTemplate {
  id: string
  name: string
  provider_type: 'oidc' | 'saml'
  issuer_url: string
  scopes: string
  /** i18n key for the template's one-line description (pages.identityProviders.templates.*). */
  descriptionKey: string
  docsUrl: string
  color: string
  /** ADFS publishes its discovery document under a path the issuer does not predict. */
  discovery_url?: string
  external_id_claim?: string
  claims_mapping?: Record<string, string>
  pass_through_params?: string[]
  /** i18n key for a setup note shown in the add dialog. */
  noteKey?: string
}

export const PROVIDER_TEMPLATES: ProviderTemplate[] = [
  {
    id: 'google',
    name: 'Google',
    provider_type: 'oidc',
    issuer_url: 'https://accounts.google.com',
    scopes: 'openid, profile, email',
    descriptionKey: 'pages.identityProviders.templates.google',
    docsUrl: 'https://developers.google.com/identity/openid-connect/openid-connect',
    color: '#4285F4',
  },
  {
    id: 'github',
    name: 'GitHub',
    provider_type: 'oidc',
    issuer_url: 'https://github.com',
    scopes: 'openid, user:email, read:user',
    descriptionKey: 'pages.identityProviders.templates.github',
    docsUrl: 'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps',
    color: '#24292e',
  },
  {
    // Entra ID v2.0. `sub` is pairwise per application, so the stable link is
    // the object id (`oid`). `acct` (0 member, 1 guest) is an optional claim.
    id: 'microsoft',
    name: 'Microsoft Entra ID',
    provider_type: 'oidc',
    issuer_url: 'https://login.microsoftonline.com/{tenant-id}/v2.0',
    scopes: 'openid, profile, email',
    descriptionKey: 'pages.identityProviders.templates.microsoft',
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc',
    color: '#0078D4',
    external_id_claim: 'oid',
    claims_mapping: {
      email: 'email',
      username: 'preferred_username',
      first_name: 'given_name',
      last_name: 'family_name',
      groups: 'groups',
    },
    pass_through_params: ['login_hint', 'prompt', 'max_age', 'domain_hint'],
    noteKey: 'pages.identityProviders.templates.microsoftNote',
  },
  {
    id: 'adfs',
    name: 'AD FS',
    provider_type: 'oidc',
    issuer_url: 'https://{adfs-host}/adfs',
    discovery_url: 'https://{adfs-host}/adfs/.well-known/openid-configuration',
    scopes: 'openid, profile, email, allatclaims',
    descriptionKey: 'pages.identityProviders.templates.adfs',
    docsUrl: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-openid-connect-oauth-concepts',
    color: '#00A4EF',
    claims_mapping: {
      email: 'email',
      username: 'upn',
      first_name: 'given_name',
      last_name: 'family_name',
      groups: 'group',
    },
    noteKey: 'pages.identityProviders.templates.adfsNote',
  },
  {
    id: 'keycloak',
    name: 'Keycloak',
    provider_type: 'oidc',
    issuer_url: 'https://{keycloak-host}/realms/{realm}',
    scopes: 'openid, profile, email',
    descriptionKey: 'pages.identityProviders.templates.keycloak',
    docsUrl: 'https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients',
    color: '#4D4D4D',
    claims_mapping: {
      email: 'email',
      username: 'preferred_username',
      first_name: 'given_name',
      last_name: 'family_name',
      groups: 'groups',
    },
  },
  {
    id: 'generic-oidc',
    name: 'Generic OIDC',
    provider_type: 'oidc',
    issuer_url: 'https://{issuer}',
    scopes: 'openid, profile, email',
    descriptionKey: 'pages.identityProviders.templates.genericOidc',
    docsUrl: 'https://openid.net/specs/openid-connect-discovery-1_0.html',
    color: '#F78C40',
  },
]
