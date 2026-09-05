/**
 * The published OpenAPI documents, in the order the API-docs page shows them.
 *
 * This list lives here rather than beside the page because three places need
 * it — the page, its own test, and the i18n key test — and while each kept its
 * own copy, retiring a spec meant editing three files and finding out from a
 * red build which one was missed. `id` is also the i18n key under
 * `pages.apiDocs.specs`, so a spec with no label fails the catalog test.
 *
 * `file` is a path under `public/api-specs/`, which the build copies from
 * `api/openapi/`.
 */
export const API_SPECS = [
  { id: 'identity', file: 'identity-service.yaml' },
  { id: 'oauth', file: 'oauth-service.yaml' },
  { id: 'admin', file: 'admin-api.yaml' },
  { id: 'access', file: 'access-service.yaml' },
  { id: 'governance', file: 'governance-service.yaml' },
  { id: 'provisioning', file: 'provisioning-service.yaml' },
  { id: 'audit', file: 'audit-service.yaml' },
  { id: 'notifications', file: 'notifications-service.yaml' },
  { id: 'portal', file: 'portal-service.yaml' },
] as const
