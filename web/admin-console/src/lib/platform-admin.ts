/**
 * True when the backend refused because the setting applies to every
 * organization on the install and the caller is not a platform administrator
 * (internal/common/middleware/platform_admin.go). An organization's admin can
 * open these pages, so the refusal has to say why rather than surface as a
 * bare 403.
 */
export function isPlatformAdminRequired(error: unknown): boolean {
  const res = (error as { response?: { status?: number; data?: { error?: unknown } } } | null)?.response
  return res?.status === 403 && res.data?.error === 'platform administrator required'
}
