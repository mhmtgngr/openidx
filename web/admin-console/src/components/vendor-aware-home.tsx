import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../lib/auth'
import { roleLevel, ROLE_LEVELS } from '../lib/roles'
import { useVendorSelf } from '../lib/external-access'

// VendorAwareHome sends an external user from the console's home to the
// vendor portal; everyone else gets the page they asked for. While the answer
// is loading for a non-staff user nothing is rendered, so a vendor never sees
// the employee dashboard flash first.
export function VendorAwareHome({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const staff = roleLevel(user?.roles ?? []) >= ROLE_LEVELS.operator
  const { data, isLoading } = useVendorSelf(!staff)
  if (!staff && isLoading) return null
  if (data?.external) return <Navigate to="/vendor" replace />
  return <>{children}</>
}
