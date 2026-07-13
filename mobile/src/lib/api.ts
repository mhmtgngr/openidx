/**
 * Shared HTTP client — the mobile analogue of web/admin-console/src/lib/api.ts.
 *
 * - Base URL is the gateway (API_BASE_URL); every service is reachable under it.
 * - Request interceptor injects `Authorization: Bearer` from the keystore and an
 *   optional `X-Org-Slug` for multi-tenant scoping.
 * - Response interceptor refreshes once on 401, then retries; a second 401 (or a
 *   failed refresh) clears tokens and signals the auth layer to route to login.
 */
import axios, {
  AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios';

import { API_BASE_URL } from '@/config';
import { refreshTokens } from '@/lib/oauth';
import {
  clearTokens,
  getAccessToken,
  getOrgSlug,
  getRefreshToken,
  setTokens,
} from '@/lib/secureStore';

/** Auth layer registers a callback so a hard 401 can force navigation to login. */
let onAuthLost: (() => void) | null = null;
export function setOnAuthLost(cb: (() => void) | null) {
  onAuthLost = cb;
}

export const client: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 20000,
});

client.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
  const token = await getAccessToken();
  if (token) config.headers.set('Authorization', `Bearer ${token}`);
  const org = await getOrgSlug();
  if (org) config.headers.set('X-Org-Slug', org);
  return config;
});

let refreshing: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  if (!refreshing) {
    refreshing = (async () => {
      const rt = await getRefreshToken();
      if (!rt) return false;
      try {
        const tokens = await refreshTokens(rt);
        await setTokens(tokens);
        return true;
      } catch {
        return false;
      } finally {
        refreshing = null;
      }
    })();
  }
  return refreshing;
}

client.interceptors.response.use(
  (r) => r,
  async (error: AxiosError) => {
    const original = error.config as
      | (InternalAxiosRequestConfig & { _retried?: boolean })
      | undefined;
    if (error.response?.status === 401 && original && !original._retried) {
      original._retried = true;
      if (await tryRefresh()) {
        const token = await getAccessToken();
        if (token) original.headers.set('Authorization', `Bearer ${token}`);
        return client(original);
      }
      await clearTokens();
      onAuthLost?.();
    }
    return Promise.reject(error);
  },
);

// Helper surface mirroring the web console's api.get/post/... shape.
export const api = {
  get: <T>(url: string, config = {}) => client.get<T>(url, config).then((r) => r.data),
  post: <T>(url: string, data?: unknown, config = {}) =>
    client.post<T>(url, data, config).then((r) => r.data),
  put: <T>(url: string, data?: unknown, config = {}) =>
    client.put<T>(url, data, config).then((r) => r.data),
  patch: <T>(url: string, data?: unknown, config = {}) =>
    client.patch<T>(url, data, config).then((r) => r.data),
  delete: <T>(url: string, config = {}) =>
    client.delete<T>(url, config).then((r) => r.data),
};
