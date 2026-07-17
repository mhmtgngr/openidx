# OpenIDX Mobile — project guide for Claude

React Native + Expo (SDK 57, TypeScript, expo-router) companion app. It is
already feature-complete and talks to the live OpenIDX backend over one HTTPS
host. Read `HANDOFF.md` and `docs/mobile-developer-guide-simple.md` (bundled in
`docs/`) before writing code.

## Golden rules
- **Expo SDK 57.** Read the exact versioned docs at
  https://docs.expo.dev/versions/v57.0.0/ before using any Expo API. APIs change
  between SDKs; do not guess.
- **One backend host.** Everything is under `API_BASE_URL`
  (`https://openidx.tdv.org`, set in `src/config.ts` / `app.json → extra`). Never
  hard-code service ports or per-service URLs.
- **Use the shared client.** `import { api } from '@/lib/api'` — it adds the
  `Authorization: Bearer` header and refreshes tokens on 401 automatically.
- **Match the existing patterns.** Every screen uses `@tanstack/react-query`
  (`useQuery`/`useMutation`), the `api` client, and `expo-router`
  `Stack.Screen`. Copy an existing screen rather than inventing a new structure.
- **Type-check before claiming done:** `npx tsc --noEmit`.

## Where things are
- `src/config.ts` — base URL, OAuth client, scopes.
- `src/lib/api.ts` — HTTP client (auto Bearer + refresh).
- `src/lib/auth.tsx`, `src/lib/oauth.ts` — OAuth PKCE + passkey login.
- `src/features/<feature>/api.ts` — the API calls per feature (approvals,
  myaccess, notifications, pam, mfa, ziti).
- `src/app/(auth)/...` and `src/app/(app)/...` — the screens (expo-router).

## Run it
```bash
npm install
npx expo start        # i = iOS sim, a = Android, or scan QR in Expo Go
```
Backend `https://openidx.tdv.org`; test login `admin` / `Admin@123`. Change the
backend via `app.json → expo.extra.apiBaseUrl`.

## What exists (don't rebuild)
Login (OAuth PKCE + passkey), MFA (TOTP, push approve, passkeys), Approvals
inbox, My Access, Notifications, PAM browse/request/launch, device enrollment +
posture. Endpoint list and sample screens are in
`docs/mobile-developer-guide-simple.md`.
