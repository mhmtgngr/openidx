export interface ProviderTemplate {
  id: string
  name: string
  provider_type: 'oidc' | 'saml'
  issuer_url: string
  scopes: string
  description: string
  docsUrl: string
  color: string
}

export const PROVIDER_TEMPLATES: ProviderTemplate[] = [
  {
    id: 'google',
    name: 'Google',
    provider_type: 'oidc',
    issuer_url: 'https://accounts.google.com',
    scopes: 'openid, profile, email',
    description: 'Google Workspace & personal accounts',
    docsUrl: 'https://developers.google.com/identity/openid-connect/openid-connect',
    color: '#4285F4',
  },
  {
    id: 'github',
    name: 'GitHub',
    provider_type: 'oidc',
    issuer_url: 'https://github.com',
    scopes: 'openid, user:email, read:user',
    description: 'GitHub personal & organization accounts',
    docsUrl: 'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps',
    color: '#24292e',
  },
  {
    id: 'microsoft',
    name: 'Microsoft Entra ID',
    provider_type: 'oidc',
    issuer_url: 'https://login.microsoftonline.com/{tenant-id}/v2.0',
    scopes: 'openid, profile, email',
    description: 'Microsoft work, school, or personal accounts',
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc',
    color: '#0078D4',
  },
]
