/**
 * Access-request approvals — the approver inbox.
 * Backend: internal/governance/workflows.go.
 */
import { api } from '@/lib/api';

export type Approval = {
  id: string;
  approver_id: string;
  approver_name: string;
  step_order: number;
  decision: 'pending' | 'approved' | 'denied';
  comments?: string;
  decided_at?: string | null;
  created_at: string;
};

export type AccessRequest = {
  id: string;
  requester_id: string;
  requester_name: string;
  resource_type: string;
  resource_id: string;
  resource_name: string;
  justification: string;
  status: 'pending' | 'approved' | 'denied' | 'fulfilled' | 'cancelled';
  priority: string;
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
  approvals?: Approval[];
};

const BASE = '/api/v1/governance';

/** Requests awaiting the current user's approval decision. */
export async function listPendingApprovals(): Promise<AccessRequest[]> {
  const r = await api.get<{ pending_approvals: AccessRequest[] }>(
    `${BASE}/my-approvals`,
  );
  return r.pending_approvals ?? [];
}

export function getRequest(id: string): Promise<AccessRequest> {
  return api.get<AccessRequest>(`${BASE}/requests/${id}`);
}

export function approveRequest(id: string, comments: string): Promise<unknown> {
  return api.post(`${BASE}/requests/${id}/approve`, { comments });
}

export function denyRequest(id: string, comments: string): Promise<unknown> {
  return api.post(`${BASE}/requests/${id}/deny`, { comments });
}
