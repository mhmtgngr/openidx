// Measures axe's color-contrast rule on the AUTHENTICATED console surfaces,
// in a real browser, in both colour schemes.
//
//   npm run build
//   npx vite preview --port 4173 &
//   node scripts/contrast-audit.mjs            # all routes below
//   ROUTES="my-security vault" node scripts/contrast-audit.mjs
//
// Exits non-zero if any route has a violation OR renders blank. Needs a
// Chromium; set CHROME to point at one (the default is this repo's CI image).
//
// WHY THIS IS NOT A CI GATE, and what covers the gap:
//   - It needs a browser and a built preview server, so it is run by hand
//     before a release, or when the palette or a theme token changes.
//   - src/test/design-token-contrast.test.ts covers the design-token pairs
//     with no browser at all, and DOES run in CI. That one catches a bad
//     token value; this one catches a bad Tailwind utility pairing.
//   - src/test/a11y.test.tsx covers the rest of the axe rule set in jsdom,
//     where color-contrast cannot run.
//
// HOW IT RENDERS AUTHENTICATED PAGES WITH NO BACKEND: the console's auth is
// entirely client-side -- it reads a JWT out of localStorage, parses it, and
// requires exp in the future and a non-empty roles claim (src/lib/auth.tsx).
// No signature check happens in the browser. So a well-formed unsigned JWT
// plus a route stub for every /api/ call is enough.
//
// The stub is deliberately PATH-AWARE and returns POPULATED data. An empty
// list renders an empty state, and an empty state has none of the badges,
// status pills and table rows that contrast bugs actually live in -- a probe
// that measures empty pages reports zero and means nothing. That is why every
// route also reports its rendered character count and axe pass count, and why
// a page that rendered nothing is called BLANK rather than counted as a pass.

import { chromium } from 'playwright'
import { readFileSync } from 'node:fs'

import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const AXE = readFileSync(resolve(ROOT, 'node_modules/axe-core/axe.min.js'), 'utf8')
const BASE = process.env.BASE || 'http://localhost:4173'
const CHROME =
  process.env.CHROME || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'
const NOW = new Date().toISOString()
const SOON = new Date(Date.now() + 86400e3 * 30).toISOString()

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

const TOKEN = [
  b64url({ alg: 'none', typ: 'JWT' }),
  b64url({
    sub: 'u-contrast-probe',
    email: 'probe@example.test',
    name: 'Contrast Probe',
    preferred_username: 'probe',
    roles: ['super_admin', 'admin', 'user'],
    groups: ['everyone'],
    permissions: ['*:*'],
    exp: Math.floor(Date.now() / 1000) + 3600,
  }),
  'unsigned',
].join('.')

// Every status/severity/risk variant is represented at least once, so each
// badge colour the design system can produce is actually painted somewhere.
const STUBS = [
  [/\/dashboard$/, {
    total_users: 128, active_users: 97, active_sessions: 23, pending_reviews: 4,
    total_applications: 17,
    security_alerts: { critical: 2, high: 5, medium: 9, low: 14, total: 30 },
    recent_events: [
      { id: 'e1', type: 'login', timestamp: NOW, actor: 'probe@example.test', action: 'sign in', outcome: 'success' },
      { id: 'e2', type: 'access_request', timestamp: NOW, actor: 'ayse@example.test', action: 'requested Finance DB', outcome: 'pending' },
      { id: 'e3', type: 'mfa', timestamp: NOW, actor: 'mert@example.test', action: 'reset factor', outcome: 'failure' },
    ],
    system_metrics: { cpu_usage: 41, memory_usage: 63, disk_usage: 28, uptime_seconds: 864000 },
  }],
  [/ziti\/status$/, { connected: true, healthy: true, controller: 'ziti.example.test', edge_routers: 3, services: 12, identities: 48, status: 'healthy' }],
  [/ziti\/sync\/status$/, { last_sync: NOW, synced: 48, pending: 2, failed: 1, status: 'ok', enabled: true }],
  [/ziti\/sync\/my-identity$/, { linked: true, enrolled: true, identity_id: 'zid-1', name: 'probe', status: 'online', enrollment_expires_at: SOON }],

  [/portal\/security-insights$/, {
    score: 72, level: 'medium', friction: 'low',
    summary: 'Your account is protected by a second factor, but one device has not checked in recently.',
    generated_by: 'rules', mfa_enrolled: true, open_alerts: 2, failed_logins_7d: 3,
    tips: ['Enrol a second device so a lost phone cannot lock you out.', 'Review the browsers you have marked trusted.'],
    devices: [
      { name: 'Work laptop', trusted: true, last_seen: NOW },
      { name: 'Personal phone', trusted: false, last_seen: NOW },
    ],
    recent_logins: [
      { at: NOW, ip_address: '10.0.0.4', location: 'Istanbul, TR', success: true, risk_score: 12 },
      { at: NOW, ip_address: '203.0.113.9', location: 'Unknown', success: false, risk_score: 88 },
    ],
  }],

  [/portal\/access-overview$/, {
    roles_count: 3, groups_count: 4, apps_count: 9, pending_requests: 2,
    roles: [{ id: 'r1', name: 'Engineer' }, { id: 'r2', name: 'On-call' }],
    groups: [{ id: 'g1', name: 'Platform' }, { id: 'g2', name: 'Everyone' }],
    privileged: { vault_grants: 2, active_checkouts: 1, active_jit_grants: 1, active_sessions: 1, pending_session_requests: 1 },
    network: { ziti_linked: true, ziti_enrolled: true, devices: 2, trusted_device: true },
  }],
  [/portal\/groups\/available$/, { groups: [{ id: 'g3', name: 'Finance', description: 'Finance systems' }] }],
  [/portal\/groups\/requests$/, { requests: [{ id: 'gr1', group_name: 'Finance', status: 'pending', created_at: NOW, justification: 'Quarter close' }] }],

  [/portal\/devices$/, {
    devices: [
      { id: 'd1', user_id: 'u', fingerprint: 'fp1', name: 'Work laptop', device_type: 'desktop', ip_address: '10.0.0.4', location: 'Istanbul, TR', trusted: true, last_seen_at: NOW, created_at: NOW },
      { id: 'd2', user_id: 'u', fingerprint: 'fp2', name: 'Personal phone', device_type: 'mobile', ip_address: '10.0.0.5', location: 'Ankara, TR', trusted: false, trust_requested: true, last_seen_at: NOW, created_at: NOW },
    ],
  }],
  [/access\/my-devices$/, {
    devices: [
      { source: 'linked', iam: { name: 'Work laptop', trusted: true, device_type: 'desktop' },
        ziti: { agent_id: 'a1', status: 'online', platform: 'windows', compliance_status: 'compliant', compliance_score: 94,
          posture: [{ check: 'disk_encryption', passed: true }, { check: 'firewall', passed: true }] } },
      { source: 'ziti',
        ziti: { agent_id: 'a2', status: 'offline', platform: 'macos', compliance_status: 'non_compliant', compliance_score: 41,
          posture: [{ check: 'disk_encryption', passed: false }, { check: 'os_version', passed: true }] } },
      { source: 'iam', iam: { name: 'Personal phone', trusted: false, device_type: 'mobile' } },
    ],
  }],

  [/my\/resources$/, {
    resources: [
      { id: 'res1', name: 'Finance database', kind: 'database', from: 'anywhere', to: 'db.internal', port: 5432, how: 'broker', status: 'ready', action: { kind: 'launch' } },
      { id: 'res2', name: 'Build server', kind: 'ssh', from: 'anywhere', to: 'build.internal', port: 22, how: 'broker', status: 'request_access', action: { kind: 'request' }, note: 'Approval required' },
      { id: 'res3', name: 'Wiki', kind: 'web', from: 'anywhere', to: 'wiki.internal', port: 443, how: 'browser', status: 'needs_setup', action: { kind: 'setup' } },
    ],
    summary: { total: 3, ready: 1 },
  }],
  [/my\/ziti\/services$/, {
    linked: true, enrolled: true,
    services: [{ name: 'wiki', description: 'Internal wiki', host: 'wiki.internal', port: 443, protocol: 'tcp' }],
  }],

  [/trusted-browsers\/check$/, { trusted: true, browser_id: 'tb1', expires_at: SOON }],
  [/trusted-browsers$/, [
    { id: 'tb1', name: 'Chrome on Windows', ip_address: '10.0.0.4', trusted_at: NOW, expires_at: SOON, last_used_at: NOW, revoked: false, active: true },
    { id: 'tb2', name: 'Safari on iPhone', ip_address: '10.0.0.5', trusted_at: NOW, expires_at: NOW, revoked: true, active: false },
  ]],

  [/governance\/requests/, {
    requests: [
      { id: 'ar1', requester_id: 'u', requester_name: 'Contrast Probe', resource_name: 'Finance database', resource_type: 'database', status: 'pending', priority: 'high', justification: 'Quarter close reconciliation', created_at: NOW, updated_at: NOW, expires_at: SOON },
      { id: 'ar2', requester_id: 'u', requester_name: 'Contrast Probe', resource_name: 'Build server', resource_type: 'server', status: 'approved', priority: 'medium', justification: 'Release build', created_at: NOW, updated_at: NOW },
      { id: 'ar3', requester_id: 'u', requester_name: 'Contrast Probe', resource_name: 'Payroll app', resource_type: 'application', status: 'denied', priority: 'low', justification: 'Curiosity', created_at: NOW, updated_at: NOW },
    ],
  }],
  [/governance\/my-approvals$/, {
    pending_approvals: [
      { id: 'ar9', requester_id: 'u2', requester_name: 'Ayse Yilmaz', resource_name: 'Prod SSH', resource_type: 'server', status: 'pending', priority: 'critical', justification: 'Incident 4821', created_at: NOW, updated_at: NOW },
    ],
  }],
  [/identity\/roles$/, [{ id: 'r1', name: 'Engineer', description: 'Standard engineer' }, { id: 'r2', name: 'On-call', description: 'Elevated during rota' }]],
  [/identity\/groups$/, [{ id: 'g1', name: 'Platform', description: 'Platform team' }]],

  [/notifications\/history$/, {
    data: [
      { id: 'n1', type: 'security_alert', channel: 'email', title: 'New sign-in from an unknown device', body: 'A sign-in happened from Ankara, TR.', link: '/my-security', read: false, metadata: {}, created_at: NOW },
      { id: 'n2', type: 'access_request', channel: 'in_app', title: 'Your request was approved', body: 'Build server access is now active.', link: '/my-access', read: true, metadata: {}, created_at: NOW },
    ],
  }],
  [/notifications\/digest$/, { data: [{ id: 'dg1', frequency: 'daily', enabled: true, last_sent_at: NOW }] }],
  [/notifications\/preferences$/, {
    preferences: [
      { channel: 'in_app', event_type: 'security_alert', enabled: true },
      { channel: 'email', event_type: 'security_alert', enabled: false },
      { channel: 'in_app', event_type: 'access_request', enabled: true },
    ],
  }],

  [/users\/me\/password-info$/, { source: 'local', is_ldap: false, is_azure_ad: false, is_directory_managed: false, password_changed_at: NOW, password_must_change: false }],
  [/users\/me\/sessions$/, {
    sessions: [
      { id: 's1', ip_address: '10.0.0.4', user_agent: 'Chrome on Windows', location: 'Istanbul, TR', created_at: NOW, last_activity: NOW, current: true },
      { id: 's2', ip_address: '203.0.113.9', user_agent: 'Safari on iPhone', location: 'Unknown', created_at: NOW, last_activity: NOW, current: false },
    ],
  }],
  [/users\/me\/tokens$/, [{ id: 'pat1', name: 'CI token', scopes: ['read'], created_at: NOW, expires_at: SOON, last_used_at: NOW, revoked: false }]],
  [/users\/me\/consents$/, [{ id: 'c1', client_id: 'grafana', client_name: 'Grafana', scopes: ['openid', 'profile'], granted_at: NOW }]],
  [/users\/me$/, {
    id: 'u-contrast-probe', email: 'probe@example.test', username: 'probe', name: 'Contrast Probe',
    first_name: 'Contrast', last_name: 'Probe', phone: '+90 555 000 0000', department: 'Platform',
    title: 'Engineer', status: 'active', mfa_enabled: true, created_at: NOW, updated_at: NOW,
    roles: ['user'], groups: ['Platform'],
  }],
  [/mfa|factors/, { factors: [{ id: 'f1', type: 'totp', name: 'Authenticator app', enabled: true, verified: true, created_at: NOW }], methods: [] }],
]

// Anything not matched above gets a BARE ARRAY: the common pattern in these
// pages is `.map` straight over the response, and an object there throws.
function bodyFor(pathname) {
  for (const [re, body] of STUBS) if (re.test(pathname)) return body
  return []
}

const ROUTES = (process.env.ROUTES || '').trim()
  ? process.env.ROUTES.trim().split(/\s+/)
  : [
      // End-user surfaces: the screens someone may have no choice about using.
      'dashboard', 'profile', 'my-access', 'my-devices', 'add-device', 'my-network',
      'my-security', 'trusted-browsers', 'access-requests', 'notification-center',
      'notification-preferences', 'device',
      // Admin surfaces: where a customer's security team spends its day.
      'users', 'groups', 'roles', 'applications', 'service-accounts', 'directories',
      'sessions', 'audit-logs', 'access-reviews', 'entitlements', 'policies',
      'zero-trust', 'ziti-network', 'proxy-routes', 'ops-cockpit', 'devices',
      'agent-fleet', 'security-alerts', 'compliance-reports', 'vault',
      'privileged-sessions', 'identity-providers', 'mfa-management', 'risk-dashboard',
    ]

const browser = await chromium.launch({ executablePath: CHROME })
const ctx = await browser.newContext()

await ctx.route('**/api/**', (route) => {
  const p = new URL(route.request().url()).pathname
  route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(bodyFor(p)) })
})
await ctx.route('**/oauth/**', (route) =>
  route.fulfill({ status: 401, contentType: 'application/json', body: '{}' }))

const page = await ctx.newPage()
const crashes = []
page.on('pageerror', (e) => crashes.push(e.message.slice(0, 200)))

await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' })
await page.evaluate((t) => localStorage.setItem('token', t), TOKEN)

let total = 0
let blank = 0
const seen = new Map()

for (const path of ROUTES) {
  for (const scheme of ['light', 'dark']) {
    crashes.length = 0
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto(`${BASE}/${path}`, { waitUntil: 'networkidle', timeout: 45000 })
    await page.waitForTimeout(1200)
    await page.addScriptTag({ content: AXE })

    const r = await page.evaluate(async () => {
      const res = await window.axe.run(document, {
        runOnly: { type: 'rule', values: ['color-contrast'] },
      })
      return {
        chars: document.body.innerText.trim().length,
        passes: res.passes.reduce((a, v) => a + v.nodes.length, 0),
        incomplete: res.incomplete.reduce((a, v) => a + v.nodes.length, 0),
        nodes: res.violations.flatMap((v) =>
          v.nodes.map((n) => ({
            target: n.target.join(' '),
            html: n.html.slice(0, 200),
            data: (n.any[0] && n.any[0].data) || {},
          }))
        ),
      }
    })

    // A page that rendered nothing cannot be judged. Say so loudly rather than
    // counting it as a pass -- that is the whole trap this probe exists to avoid.
    const rendered = r.chars > 0 && r.passes > 0
    if (!rendered) blank++
    total += r.nodes.length
    console.log(
      `${!rendered ? 'BLANK' : r.nodes.length === 0 ? 'ok   ' : 'FAIL '} ` +
        `${path} [${scheme}] violations=${r.nodes.length} passes=${r.passes} ` +
        `incomplete=${r.incomplete} chars=${r.chars}` +
        (crashes.length ? `  CRASH: ${crashes[0]}` : '')
    )
    for (const n of r.nodes) {
      const key = `${n.target}|${scheme}`
      if (!seen.has(key)) seen.set(key, { ...n, scheme, path })
    }
  }
}

console.log(`\n=== ${total} violations, ${seen.size} distinct, ${blank} blank page(s) ===\n`)
for (const n of seen.values()) {
  const d = n.data
  console.log(
    `[${n.scheme}] ${n.path}  ratio=${d.contrastRatio} need=${d.expectedContrastRatio} ` +
      `fg=${d.fgColor} bg=${d.bgColor} size=${d.fontSize}/${d.fontWeight}`
  )
  console.log(`   ${n.target}`)
  console.log(`   ${n.html.replace(/\s+/g, ' ')}\n`)
}

await browser.close()
process.exit(total === 0 && blank === 0 ? 0 : 1)
