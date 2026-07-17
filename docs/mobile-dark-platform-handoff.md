# OpenIDX Mobile — Developer Handoff (post dark-platform changes)

This is what to give the mobile developer after the dark-platform hardening.
**TL;DR: nothing in the mobile app broke.** The app already talks to the platform
only through the public edge (`https://openidx.tdv.org`), and the hardening we
shipped (Option B: closing the raw host-IP:port bypass) does not touch the edge.
The one new, mobile-relevant capability is the **Tier-0 enroll door**, now wired
into the app.

---

## 1. What changed on the backend (and why the app is unaffected)

We hardened the reference deployment so the management/identity services
(`identity, governance, provisioning, audit, admin-api`) are **no longer
reachable on the host's external IP:port** — they bind loopback and are served
only via the APISIX edge. Public HTTPS (`https://openidx.tdv.org`) is unchanged.

| Path the app uses | Before | After | Impact on app |
|---|---|---|---|
| `https://openidx.tdv.org/oauth/*` (login) | public | public | none |
| `https://openidx.tdv.org/api/v1/*` (all features) | public via edge | public via edge | none |
| `http://<host-ip>:8001…8005` (raw port) | open (bypass) | **closed** | none (app never used it) |

Because `mobile/src/config.ts` points `API_BASE_URL` at the edge host and every
service is reached under it, **no mobile code change was required for the app to
keep working.** Verified live: full OAuth+PKCE login still issues real tokens.

### New capability wired in: the dark enroll door
`POST /api/v1/access/enroll` is the single public "front door" that stays open
even if the platform is later taken fully dark. It trades the signed-in session
(or an admin/MDM enrollment token) for a one-time **OpenZiti enrollment JWT** the
native Ziti module uses to join the overlay. Contract:

```http
POST /api/v1/access/enroll        Host: openidx.tdv.org
Authorization: Bearer <access_token>      # session path (self-service)
Content-Type: application/json
{}                                         # or {"enrollment_token":"<mdm-token>"}

200 OK
{ "ziti_enrollment_jwt": "<jwt>", "identity_name": "user-<id>-<device>" }
401 { "error": "no valid entitlement (session/token/passkey)" }   # fail-closed
```

Now available in the app as `requestZitiEnrollmentJwt()` (see §3) and used as a
fallback in the **This device** screen.

---

## 2. What to hand the developer

| Item | Value / where |
|---|---|
| Repo | `mhmtgngr/openidx`, work in `mobile/` |
| Backend | `https://openidx.tdv.org` (reference box). Split-DNS: add `*.tdv.org` to their hosts/VPN, or give a staging URL |
| Test user | a normal login (e.g. `admin` / `Admin@123` on the ref box) |
| API base override | `mobile/app.json → expo.extra.apiBaseUrl` (defaults to `https://openidx.tdv.org`) |
| Full API contract | [`docs/mobile-authenticator-developer-guide.md`](./mobile-authenticator-developer-guide.md) |
| Build/secrets handoff | [`mobile/HANDOFF.md`](../mobile/HANDOFF.md) (Expo/EAS, Apple, Play, FCM/APNs) |
| Dark-platform context | [`OPENIDX_ZITI_ARCHITECTURE.md → Dark platform`](./OPENIDX_ZITI_ARCHITECTURE.md#dark-platform-cutover-staged-verify-before-cutover) |

**Nothing about the hardening blocks the developer.** Point them at the edge host
and they build/run exactly as before. If the platform is ever taken *fully* dark
(Option A, not done), the app's Ziti path (§3) becomes the way in, and the
`requestZitiEnrollmentJwt()` door is already there.

---

## 3. The mobile enroll code (already added)

`mobile/src/features/ziti/device.ts`:

```ts
/**
 * Dark-platform enroll door (Tier-0): POST /api/v1/access/enroll.
 * Trades the signed-in session for a one-time OpenZiti enrollment JWT.
 */
export async function requestZitiEnrollmentJwt(enrollmentToken?: string): Promise<string> {
  const res = await api.post<{ ziti_enrollment_jwt: string; identity_name: string }>(
    `${BASE}/enroll`,                                    // BASE = '/api/v1/access'
    enrollmentToken ? { enrollment_token: enrollmentToken } : {},
  );
  if (res.ziti_enrollment_jwt) await SecureStore.setItemAsync(ZITI_JWT, res.ziti_enrollment_jwt);
  return res.ziti_enrollment_jwt;
}
```

Wired into the **This device** screen's enroll flow as a fallback:

```ts
if (zitiAvailable()) {
  // Prefer the JWT from agent-enroll; if absent (or platform is dark),
  // fall back to the Tier-0 enroll door.
  const jwt = (await getZitiJwt()) ?? (await requestZitiEnrollmentJwt());
  if (jwt) await zitiEnroll(jwt);
}
```

---

## 4. Sample views (reference screens the developer can build against)

The app already ships these screens (`mobile/src/app/`). They are the canonical
patterns: `@tanstack/react-query` for data, the shared `api` client (auto Bearer
+ refresh), `expo-router` `Stack.Screen` for the title. Reuse the style.

### 4a. Login (`(auth)/login.tsx`) — OAuth/PKCE + passkey

```tsx
export default function LoginScreen() {
  const { loginWithBrowser, loginWithPasskey } = useAuth();
  const canPasskey = passkeysSupported();
  // "Sign in with passkey" (native) OR "Sign in" (OAuth PKCE in a browser tab).
  // Both resolve to tokens in the secure store; the api client uses them.
  return (
    <View style={styles.container}>
      <Text style={styles.title}>OpenIDX</Text>
      {canPasskey && <Pressable onPress={() => run(loginWithPasskey)}>…passkey…</Pressable>}
      <Pressable onPress={() => run(loginWithBrowser)}>…OAuth…</Pressable>
    </View>
  );
}
```

### 4b. This device (`(app)/security/device.tsx`) — enroll + posture + **overlay**

The dark-platform-relevant screen. Shows enrollment status, the OpenZiti overlay
state, a one-tap **Enroll** (which now also mints the Ziti JWT via the enroll
door), and posture reporting.

```tsx
const enroll = useMutation({
  mutationFn: async () => {
    await enrollDevice();                                  // POST /agent/enroll/oauth
    if (zitiAvailable()) {
      const jwt = (await getZitiJwt()) ?? (await requestZitiEnrollmentJwt());
      if (jwt) await zitiEnroll(jwt);                      // native overlay join
    }
  },
  onSuccess: () => Alert.alert('Enrolled', 'This device is now managed by OpenIDX.'),
});
// UI: status card ("✓ Enrolled & managed" / "OpenZiti: <status>"), Enroll button,
//     posture rows (🟢/🔴/⚪), "Report posture now".
```

### 4c. My Access (`(app)/my-access.tsx`) — a read-only data screen pattern

```tsx
const { data, isLoading } = useQuery({ queryKey: ['my-requests'], queryFn: listMyRequests });
// Renders claim chips (roles/groups from the token) + the user's access requests.
// GET /api/v1/access/... through the edge; unchanged by the hardening.
```

### 4d. Approvals inbox (`(app)/approvals/`) — action screen pattern

```tsx
// list:   GET  /api/v1/governance/requests            (pending approvals)
// approve:POST /api/v1/governance/requests/:id/approve
// deny:   POST /api/v1/governance/requests/:id/deny
```

All four hit the same edge host and are **unaffected by the dark cutover**.

---

## 5. Reachability checklist for the developer

- App → `https://openidx.tdv.org/oauth/*` and `/api/v1/*`: **works** (edge).
- App never used raw `host-IP:port`, so closing it changes nothing.
- If a fully-dark deployment is used later: the device must enroll over the
  overlay first — call `requestZitiEnrollmentJwt()` (already wired), have the
  native `OidxZiti` module `enroll(jwt)`, then all `/api/v1/*` calls tunnel.
  The `modules/ziti/` native module still needs to be compiled (see
  `mobile/HANDOFF.md §5`); until then the app runs against the public edge.
