import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'
import axe from 'axe-core'

// Accessibility gate for the surfaces a person outside the admin team reaches:
// the pre-login flows and the end-user pages. Those are the screens someone
// may have no choice about using -- an employee enrolling a device, a person
// approving a device code on their phone -- so a control a screen reader
// cannot name is a defect there in a way it is not on an internal dashboard.
//
// WHAT THIS GATE DOES NOT COVER, and why it must not be read as "the console
// is accessible":
//
//   - Colour contrast. axe's contrast rule needs real layout and paint;
//     jsdom does not implement getComputedStyle for pseudo-elements, so the
//     rule cannot run and is disabled below rather than left to log errors
//     and silently pass. Contrast needs a browser run.
//   - Keyboard order, focus management on route change and dialog close, and
//     whether async updates are announced. axe does not test any of these in
//     any environment; they need a person with a keyboard and a screen reader.
//
// So this is the automatable subset, not a VPAT. What it does buy is that the
// subset cannot regress unnoticed -- which is what happened to the fourteen
// unnamed toggles on the notification-preferences page that writing it found.

vi.mock('../lib/auth', () => ({
  useAuth: () => ({
    login: vi.fn(),
    logout: vi.fn(),
    isAuthenticated: true,
    isLoading: false,
    user: { id: 'u1', email: 'a@b.test', name: 'A B', roles: ['user'] },
    hasRole: () => true,
    hasPermission: () => true,
  }),
}))

// Every API call resolves empty. The gate is about the markup a page emits,
// not about its data, and an empty result still renders the chrome, headings,
// tables and controls that carry the accessibility properties.
vi.mock('../lib/api', () => ({
  api: new Proxy({} as Record<string, unknown>, {
    get: (_t, k) =>
      k === 'then'
        ? undefined
        : new Proxy({} as Record<string, unknown>, {
            get: (_t2, k2) =>
              k2 === 'then' ? undefined : vi.fn(() => Promise.resolve([])),
          }),
  }),
  baseURL: 'http://localhost:8001',
  getOAuthURL: vi.fn(() => 'http://localhost:8001'),
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { LoginPage } from '../pages/login'
import { ForgotPasswordPage } from '../pages/forgot-password'
import { ResetPasswordPage } from '../pages/reset-password'
import { MagicLinkVerifyPage } from '../pages/magic-link-verify'
import { DeviceAuthorizationPage } from '../pages/device-authorization'
import { MySecurityPage } from '../pages/my-security'
import { MyAccessPage } from '../pages/my-access'
import { MyDevicesPage } from '../pages/my-devices'
import { MyNetworkPage } from '../pages/my-network'
import { NotificationPreferencesPage } from '../pages/notification-preferences'
import { TrustedBrowsersPage } from '../pages/trusted-browsers'
import { AccessRequestsPage } from '../pages/access-requests'
import { AddDevicePage } from '../pages/add-device'

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

async function violationsIn(container: HTMLElement) {
  const results = await axe.run(container, {
    runOnly: {
      type: 'tag',
      values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'],
    },
    // See the header: this rule cannot run in jsdom. Disabling it is the
    // honest option -- leaving it enabled makes axe throw internally, log,
    // and report nothing, which looks exactly like a pass.
    rules: { 'color-contrast': { enabled: false } },
  })
  return results.violations.map(
    (v) =>
      `[${v.impact}] ${v.id} (${v.nodes.length} node(s)): ${v.help}\n` +
      v.nodes
        .slice(0, 5)
        .map((n) => '      ' + n.html.slice(0, 200))
        .join('\n')
  )
}

// Pre-login first: these are reachable by anyone, in any state, and two of
// them (device authorization, magic-link verify) are opened on a phone by
// someone who did not choose this software.
const surfaces: Array<[string, () => React.ReactElement]> = [
  ['login', () => <LoginPage />],
  ['forgot-password', () => <ForgotPasswordPage />],
  ['reset-password', () => <ResetPasswordPage />],
  ['magic-link-verify', () => <MagicLinkVerifyPage />],
  ['device-authorization', () => <DeviceAuthorizationPage />],
  ['my-security', () => <MySecurityPage />],
  ['my-access', () => <MyAccessPage />],
  ['my-devices', () => <MyDevicesPage />],
  ['my-network', () => <MyNetworkPage />],
  ['notification-preferences', () => <NotificationPreferencesPage />],
  ['trusted-browsers', () => <TrustedBrowsersPage />],
  ['access-requests', () => <AccessRequestsPage />],
  ['add-device', () => <AddDevicePage />],
]

describe('accessibility (axe, WCAG 2.1 A/AA subset)', () => {
  for (const [name, make] of surfaces) {
    it(`${name} has no WCAG A/AA violations axe can detect`, async () => {
      // A render failure is a failure, not a skip: silently dropping a
      // surface is how a coverage list rots into a list of the easy ones.
      const { container } = render(wrap(make()))
      const violations = await violationsIn(container)
      expect(violations.join('\n')).toBe('')
    }, 30000)
  }

  // A gate that cannot go red is worse than no gate -- the same rule the Go
  // and shell checkers in this repo follow. This proves the runner, the tag
  // selection and the assertion actually catch the defect class that the
  // notification-preferences toggles were in.
  it('goes red on an unnamed control', async () => {
    const { container } = render(
      <div>
        <button type="button">
          <span className="icon" />
        </button>
        <input type="text" />
      </div>
    )
    const violations = await violationsIn(container)
    expect(violations.join('\n')).toContain('button-name')
  })
})
