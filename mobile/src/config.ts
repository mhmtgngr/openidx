/**
 * Runtime configuration for the OpenIDX mobile app.
 *
 * Values resolve from `expo-constants` `extra` (set per EAS build profile in
 * app.json / eas.json), falling back to the reference-box defaults so a dev
 * build works out of the box. The API base URL fronts every service through
 * the gateway; the OAuth issuer is the same host with the `/oauth` prefix.
 */
import Constants from 'expo-constants';

type Extra = {
  apiBaseUrl?: string;
  oauthClientId?: string;
  oauthScopes?: string;
};

const extra = (Constants.expoConfig?.extra ?? {}) as Extra;

/** Gateway base URL — all `/api/v1/*` and `/oauth/*` calls go here. */
export const API_BASE_URL: string =
  extra.apiBaseUrl ?? 'https://openidx.tdv.org';

/** OAuth issuer/base. OpenIDX serves OAuth under `/oauth` on the gateway host. */
export const OAUTH_BASE_URL = `${API_BASE_URL}/oauth`;

/** Native/public OAuth client registered server-side (see plan: backend prereq). */
export const OAUTH_CLIENT_ID: string = extra.oauthClientId ?? 'openidx-mobile';

/** Custom scheme redirect target (must match app.json `scheme`). */
export const OAUTH_REDIRECT_SCHEME = 'openidx';
export const OAUTH_REDIRECT_URI = `${OAUTH_REDIRECT_SCHEME}://oauth-callback`;

export const OAUTH_SCOPES: string[] = (
  extra.oauthScopes ?? 'openid profile email offline_access'
).split(/\s+/);
