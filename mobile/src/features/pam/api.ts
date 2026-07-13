/**
 * PAM connection self-service. Backend: internal/access/pam_launch.go,
 * pam_entries.go (mounted under /api/v1/access).
 */
import { api } from '@/lib/api';

const BASE = '/api/v1/access/pam';

export type PamEntry = {
  id: string;
  name: string;
  entry_type: string; // ssh | rdp | vnc | telnet | website | credential | folder
  folder_id?: string | null;
  tags?: string[];
  require_approval: boolean;
  record_session: boolean;
  reach_mode?: 'direct' | 'ziti';
  hostname?: string;
  port?: number;
  favorite?: boolean;
};

export type PamConnectResult = {
  launch_type: 'guacamole' | 'url';
  connect_url?: string;
  url?: string;
  entry_id: string;
  session_id?: string;
  credential_injected?: boolean;
  recorded?: boolean;
  reach_mode?: 'direct' | 'ziti';
};

export type PamEntryRequest = {
  id: string;
  entry_id: string;
  entry_name: string;
  entry_type: string;
  reason: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  decided_at?: string | null;
  expires_at?: string | null;
  created_at: string;
};

/** Error thrown when a launch needs an approved access request first. */
export class ApprovalRequiredError extends Error {
  constructor() {
    super('This connection requires an approved access request.');
    this.name = 'ApprovalRequiredError';
  }
}

export async function listEntries(query?: string): Promise<PamEntry[]> {
  const qs = query ? `?q=${encodeURIComponent(query)}` : '';
  const r = await api.get<{ entries: PamEntry[] }>(`${BASE}/entries${qs}`);
  return r.entries ?? [];
}

export function requestAccess(id: string, reason: string): Promise<{ request_id: string }> {
  return api.post<{ request_id: string }>(`${BASE}/entries/${id}/request`, { reason });
}

export async function listMyEntryRequests(): Promise<PamEntryRequest[]> {
  const r = await api.get<{ requests: PamEntryRequest[] }>(`${BASE}/my-entry-requests`);
  return r.requests ?? [];
}

export async function connect(id: string): Promise<PamConnectResult> {
  try {
    return await api.post<PamConnectResult>(`${BASE}/entries/${id}/connect`, {});
  } catch (e: unknown) {
    const status = (e as { response?: { status?: number } })?.response?.status;
    if (status === 403) throw new ApprovalRequiredError();
    throw e;
  }
}

export function endSession(sessionId: string): Promise<unknown> {
  return api.post(`${BASE}/sessions/${sessionId}/end`, {});
}
