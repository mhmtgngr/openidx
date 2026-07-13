/**
 * "My Access" — the caller's own access requests. Backend:
 * internal/governance (requests?requester_id=me). Entitlements (roles/groups)
 * come from the JWT claims, so no extra call is needed for those.
 */
import type { AccessRequest } from '@/features/approvals/api';
import { api } from '@/lib/api';

export async function listMyRequests(): Promise<AccessRequest[]> {
  const r = await api.get<{ requests: AccessRequest[] }>(
    '/api/v1/governance/requests?requester_id=me&limit=50',
  );
  return r.requests ?? [];
}
