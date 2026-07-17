# OpenIDX Mobile — Developer Guide (what you can access and build)

React Native + Expo (SDK 57, TypeScript, expo-router) app in `mobile/`. It is
feature-complete and talks to the live backend over one HTTPS host. This is the
short version: set it up, know the endpoints, copy the screen patterns.

---

## 1. Set up (5 minutes)

```bash
cd mobile
npm install
npx expo start          # press i (iOS sim), a (Android), or scan the QR with Expo Go
```

- **Backend:** `https://openidx.tdv.org` (already running). If you can't resolve
  `*.tdv.org`, add it to your hosts/VPN or ask for a staging URL.
- **Test login:** `admin` / `Admin@123`.
- **Change the backend URL:** `mobile/app.json → expo.extra.apiBaseUrl`.

That's all you need. Everything the app uses is under that one host.

---

## 2. How the app talks to the backend

One base URL, every service under it. You never hard-code service ports.

| Thing | Where |
|---|---|
| Base URL | `mobile/src/config.ts` → `API_BASE_URL` (`https://openidx.tdv.org`) |
| HTTP client | `mobile/src/lib/api.ts` → `api.get/post/put/patch/delete` |
| Auth | client auto-adds `Authorization: Bearer` and refreshes on 401 |
| Login | `mobile/src/lib/auth.tsx` (OAuth PKCE) + `features/mfa/passkey.ts` (passkey) |

Use `api` and it just works:

```ts
import { api } from '@/lib/api';
const data = await api.get<MyType>('/api/v1/identity/notifications');
await api.post('/api/v1/governance/requests/123/approve', { comments: 'ok' });
```

---

## 3. What you can access (the endpoints, by feature)

All relative to `https://openidx.tdv.org`. These are the ones the app already
calls; the same client can reach any `/api/v1/*` or `/oauth/*` route.

| Feature | Code | Endpoints |
|---|---|---|
| **Login** | `lib/auth.tsx`, `lib/oauth.ts` | `GET /oauth/authorize`, `POST /oauth/token`, `POST /oauth/logout` |
| **Passkeys / MFA** | `features/mfa/` | passkey enroll + TOTP under `/oauth/*` and `/api/v1/identity/*` |
| **My Access** | `features/myaccess/api.ts` | `GET /api/v1/access/...` (the user's roles/groups/requests) |
| **Approvals** | `features/approvals/api.ts` | `GET /api/v1/governance/requests`, `POST .../requests/:id/approve`, `.../deny` |
| **Notifications** | `features/notifications/api.ts` | `GET /api/v1/identity/notifications`, `.../unread-count`, `POST .../mark-read`, `.../mark-all-read` |
| **PAM (remote access)** | `features/pam/api.ts` | `GET /api/v1/access/pam/entries`, `POST .../entries/:id/request`, `.../connect`, `.../sessions/:id/end` |
| **This device** | `features/ziti/device.ts` | `POST /api/v1/access/agent/enroll/oauth`, `POST .../agent/report` |

Full request/response contract with examples:
[`docs/mobile-authenticator-developer-guide.md`](./mobile-authenticator-developer-guide.md).

---

## 4. Sample views (copy these patterns)

The app already ships these. Every screen uses the same recipe: `@tanstack/
react-query` for data, the shared `api` client, `expo-router` `Stack.Screen`
for the title. Build new screens the same way.

### 4a. Login — `src/app/(auth)/login.tsx`
Two buttons: passkey (native) or OAuth (browser tab). Both end with tokens in
the secure store; the `api` client uses them automatically.

```tsx
export default function LoginScreen() {
  const { loginWithBrowser, loginWithPasskey } = useAuth();
  return (
    <View style={styles.container}>
      <Text style={styles.title}>OpenIDX</Text>
      {passkeysSupported() && <Pressable onPress={() => run(loginWithPasskey)}><Text>Sign in with passkey</Text></Pressable>}
      <Pressable onPress={() => run(loginWithBrowser)}><Text>Sign in</Text></Pressable>
    </View>
  );
}
```

### 4b. Read screen — `src/app/(app)/my-access.tsx`
Fetch with react-query, show a spinner, render the list. This is the template
for any "show me data" screen.

```tsx
const { data, isLoading } = useQuery({ queryKey: ['my-requests'], queryFn: listMyRequests });
if (isLoading) return <ActivityIndicator />;
// render claim chips (roles/groups) + the user's requests
```

### 4c. Action screen — `src/app/(app)/approvals/`
List + act (approve/deny) with a mutation, then invalidate the query to refresh.

```tsx
const list = useQuery({ queryKey: ['approvals'], queryFn: listPendingApprovals });
const approve = useMutation({
  mutationFn: (id: string) => approveRequest(id, 'looks good'),   // POST .../requests/:id/approve
  onSuccess: () => qc.invalidateQueries({ queryKey: ['approvals'] }),
});
```

### 4d. This device — `src/app/(app)/security/device.tsx`
Enroll the phone as a managed device + report posture. One-tap enroll, status
card, posture rows.

```tsx
const enroll = useMutation({ mutationFn: enrollDevice });          // POST /api/v1/access/agent/enroll/oauth
// UI: "✓ Enrolled & managed" card, Enroll button, posture 🟢/🔴/⚪, "Report posture now"
```

---

## 5. Build / release

For real device builds and store distribution (Expo/EAS, Apple, Google Play,
push) see [`mobile/HANDOFF.md`](../mobile/HANDOFF.md). For day-to-day development
you only need §1 above.
