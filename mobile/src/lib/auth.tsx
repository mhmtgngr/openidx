/**
 * Auth provider — the mobile analogue of web/admin-console/src/lib/auth.tsx.
 *
 * Drives the OAuth Authorization-Code + PKCE login via expo-auth-session
 * (browser hop to /oauth/authorize/v2), exchanges the code through oauth.ts,
 * stores tokens in the keystore, parses JWT claims for the UI, and keeps the
 * access token fresh with a background refresh timer.
 */
import * as AuthSession from 'expo-auth-session';
import { useRouter } from 'expo-router';
import * as WebBrowser from 'expo-web-browser';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';

import {
  OAUTH_BASE_URL,
  OAUTH_CLIENT_ID,
  OAUTH_REDIRECT_SCHEME,
  OAUTH_SCOPES,
} from '@/config';
import { setOnAuthLost } from '@/lib/api';
import { decodeClaims, type Claims } from '@/lib/jwt';
import { exchangeCode, refreshTokens, revokeSession } from '@/lib/oauth';
import {
  clearTokens,
  getAccessToken,
  getExpiresAt,
  getRefreshToken,
  setTokens,
  type Tokens,
} from '@/lib/secureStore';

WebBrowser.maybeCompleteAuthSession();

const discovery: AuthSession.DiscoveryDocument = {
  authorizationEndpoint: `${OAUTH_BASE_URL}/authorize/v2`,
  tokenEndpoint: `${OAUTH_BASE_URL}/token`,
};

type AuthState = {
  claims: Claims | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  loginWithBrowser: () => Promise<void>;
  /** Passkey/other flows that already obtained tokens hand them here. */
  loginWithTokens: (t: Tokens) => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [claims, setClaims] = useState<Claims | null>(null);
  const [isLoading, setLoading] = useState(true);
  const router = useRouter();
  const refreshTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const applyToken = useCallback(async () => {
    const token = await getAccessToken();
    setClaims(decodeClaims(token));
  }, []);

  const loginWithTokens = useCallback(
    async (t: Tokens) => {
      await setTokens(t);
      await applyToken();
    },
    [applyToken],
  );

  const logout = useCallback(async () => {
    const token = await getAccessToken();
    if (token) await revokeSession(token);
    await clearTokens();
    setClaims(null);
    router.replace('/(auth)/login');
  }, [router]);

  const loginWithBrowser = useCallback(async () => {
    const redirectUri = AuthSession.makeRedirectUri({
      scheme: OAUTH_REDIRECT_SCHEME,
      path: 'oauth-callback',
    });
    const request = new AuthSession.AuthRequest({
      clientId: OAUTH_CLIENT_ID,
      scopes: OAUTH_SCOPES,
      redirectUri,
      responseType: AuthSession.ResponseType.Code,
      usePKCE: true,
    });
    const result = await request.promptAsync(discovery);
    if (result.type !== 'success' || !result.params.code) {
      throw new Error(
        result.type === 'error'
          ? (result.params.error_description ?? 'authorization failed')
          : 'authorization cancelled',
      );
    }
    const tokens = await exchangeCode(
      result.params.code,
      request.codeVerifier ?? '',
      redirectUri,
    );
    await loginWithTokens(tokens);
  }, [loginWithTokens]);

  // Bootstrap: load a stored token, refresh if expired, else clear.
  useEffect(() => {
    setOnAuthLost(() => {
      setClaims(null);
      router.replace('/(auth)/login');
    });
    (async () => {
      try {
        const token = await getAccessToken();
        if (!token) return;
        const exp = await getExpiresAt();
        if (exp > Math.floor(Date.now() / 1000) + 5) {
          await applyToken();
          return;
        }
        const rt = await getRefreshToken();
        if (rt) {
          const tokens = await refreshTokens(rt);
          await setTokens(tokens);
          await applyToken();
        } else {
          await clearTokens();
        }
      } catch {
        await clearTokens();
      } finally {
        setLoading(false);
      }
    })();
    return () => setOnAuthLost(null);
  }, [applyToken, router]);

  // Background refresh: when <60s to expiry, refresh proactively.
  useEffect(() => {
    if (!claims) return;
    refreshTimer.current = setInterval(async () => {
      const exp = await getExpiresAt();
      if (exp - Math.floor(Date.now() / 1000) > 60) return;
      const rt = await getRefreshToken();
      if (!rt) return;
      try {
        const tokens = await refreshTokens(rt);
        await setTokens(tokens);
        await applyToken();
      } catch {
        // interceptor will handle a hard failure on the next call
      }
    }, 30000);
    return () => {
      if (refreshTimer.current) clearInterval(refreshTimer.current);
    };
  }, [claims, applyToken]);

  return (
    <AuthContext.Provider
      value={{
        claims,
        isAuthenticated: !!claims,
        isLoading,
        loginWithBrowser,
        loginWithTokens,
        logout,
      }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
