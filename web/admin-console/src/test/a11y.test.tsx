import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'
import axe from 'axe-core'

// Accessibility gate for EVERY page in the console.
//
// It used to name thirteen surfaces by hand -- the pre-login flows and the
// end-user pages -- on the reasoning that those are the screens someone may
// have no choice about using. That reasoning was right about priority and
// wrong about scope: it left ninety-four admin pages ungated, and they held
// twenty-nine violations of exactly the class the gate was written to catch.
// Sixteen filter dropdowns announced nothing at all; five filters on the admin
// audit log had visible labels that were bare <label> elements with no htmlFor,
// so a sighted operator saw five named controls and a screen reader heard five
// anonymous ones; the landing page's mobile menu button had no name; and Access
// 360 wrapped a <Button> inside a <Link>, which is invalid HTML and produced
// both a nameless link and a nameless button. An admin who uses a screen reader
// is not a lesser user, and "the surfaces that matter" is not a list anyone
// keeps up to date.
//
// So the list is now derived, not written: every file in ../pages is a case.
// A page added tomorrow is covered the day it lands, with no edit here.
//
// WHAT THIS GATE DOES NOT COVER, and why it must not be read as "the console
// is accessible":
//
//   - Colour contrast. axe's contrast rule needs real layout and paint; jsdom
//     does not implement getComputedStyle for pseudo-elements, so the rule
//     cannot run and is disabled below rather than left to log errors and
//     silently pass. design-token-contrast.test.ts checks the palette itself,
//     and scripts/contrast-audit.mjs checks rendered pages in a real browser.
//   - Anything behind an interaction. Dialog bodies, popovers and dropdown
//     menus are not mounted until opened, so their controls are invisible to
//     this gate even though they are part of the page.
//   - Keyboard order, focus management on route change and dialog close, and
//     whether async updates are announced. axe does not test any of these in
//     any environment. scripts/check-keyboard-reachable.sh covers the static
//     half of the first one; the rest needs a person with a screen reader.
//
// So this is the automatable subset, not a VPAT.

vi.mock('../lib/auth', () => ({
  useAuth: () => ({
    login: vi.fn(),
    logout: vi.fn(),
    isAuthenticated: true,
    isLoading: false,
    user: { id: 'u1', email: 'a@b.test', name: 'A B', roles: ['admin'] },
    hasRole: () => true,
    hasPermission: () => true,
  }),
  AuthProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))

// Every API call resolves to an empty result. The gate is about the markup a
// page emits, not about its data, and an empty result still renders the
// chrome, headings, filters and controls that carry the accessibility
// properties.
//
// It has to be empty in a shape-tolerant way. Resolving a bare [] looks right
// until a page reads `data.entries`, which on an array is
// Array.prototype.entries -- a function -- so `(data.entries || []).filter(…)`
// throws and the page never renders. That is not a defect in the page; it is
// the stub lying about the response shape, and it silently removed pages from
// an earlier version of this sweep. An empty array whose unknown properties
// resolve to another one satisfies both `data.map(…)` and `data.entries.filter(…)`.
const ARRAY_MEMBERS = new Set([
  'length', 'map', 'filter', 'forEach', 'slice', 'reduce', 'reduceRight',
  'find', 'findIndex', 'some', 'every', 'sort', 'concat', 'join', 'indexOf',
  'lastIndexOf', 'includes', 'flatMap', 'flat', 'at', 'reverse', 'push', 'pop',
  'shift', 'unshift', 'splice', 'fill', 'keys', 'toString', 'constructor',
])
function emptyResult(): unknown {
  const target: unknown[] = []
  return new Proxy(target, {
    get(t, prop, recv) {
      if (typeof prop === 'symbol') return Reflect.get(t, prop, recv)
      if (prop === 'then') return undefined // must not look like a promise
      if (ARRAY_MEMBERS.has(prop) || /^\d+$/.test(prop)) {
        return Reflect.get(t, prop, recv)
      }
      return emptyResult()
    },
  })
}

vi.mock('../lib/api', () => ({
  api: new Proxy({} as Record<string, unknown>, {
    get: (_t, k) =>
      k === 'then'
        ? undefined
        : new Proxy({} as Record<string, unknown>, {
            get: (_t2, k2) =>
              k2 === 'then' ? undefined : vi.fn(() => Promise.resolve(emptyResult())),
          }),
  }),
  baseURL: 'http://localhost:8001',
  getOAuthURL: vi.fn(() => 'http://localhost:8001'),
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

// Pages that cannot be rendered in this environment at all, with the reason.
// Each one still gets a test -- see below -- that fails if it starts working,
// because an unchecked exception list is how a coverage sweep quietly becomes
// a list of the easy cases.
const UNRENDERABLE: Record<string, string> = {
  'api-docs':
    'swagger-ui-react bundles its own copy of React, so rendering it here ' +
    'throws "A React Element from an older version of React was rendered".',
}

// Recursive: a page in a subdirectory is still a page a user reaches.
const modules = import.meta.glob('../pages/**/*.tsx')

function pageName(path: string): string {
  return path.split('/').pop()!.replace(/\.tsx$/, '')
}

async function loadComponent(path: string): Promise<React.ComponentType> {
  const mod = (await modules[path]()) as Record<string, unknown>
  // Pages export either a named `SomethingPage` or a default. Both are used in
  // this codebase, and only looking for the first cost an earlier sweep two
  // whole pages -- one of which had two unnamed filters.
  for (const [key, value] of Object.entries(mod)) {
    if (typeof value === 'function' && (key === 'default' || /^[A-Z]/.test(key))) {
      return value as React.ComponentType
    }
  }
  throw new Error(`no component export found in ${path}`)
}

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

const pagePaths = Object.keys(modules)
  .filter((p) => !/\.test\.tsx$/.test(p))
  .sort()

describe('accessibility (axe, WCAG 2.1 A/AA subset)', () => {
  // If the glob ever stops matching -- a moved directory, a changed extension
  // -- every case below silently disappears and the suite goes green with
  // nothing checked. Pin the shape of the sweep itself.
  it('sweeps the whole pages directory', () => {
    expect(pagePaths.length).toBeGreaterThan(90)
  })

  for (const path of pagePaths) {
    const name = pageName(path)
    if (name in UNRENDERABLE) continue
    it(`${name} has no WCAG A/AA violations axe can detect`, async () => {
      // A render failure is a failure, not a skip: silently dropping a
      // surface is how a coverage list rots into a list of the easy ones.
      const Component = await loadComponent(path)
      const { container } = render(wrap(<Component />))
      const violations = await violationsIn(container)
      expect(violations.join('\n')).toBe('')
    }, 30000)
  }

  // The exception list has to be able to go red too. If one of these starts
  // rendering, this fails and the entry gets deleted -- rather than sitting
  // there forever exempting a page that no longer needs exempting.
  for (const [name, reason] of Object.entries(UNRENDERABLE)) {
    it(`${name} is still unrenderable here (${reason})`, async () => {
      const path = pagePaths.find((p) => pageName(p) === name)
      expect(path, `${name} is on the exception list but is not a page`).toBeDefined()
      const Component = await loadComponent(path!)
      expect(() => render(wrap(<Component />))).toThrow()
    }, 30000)
  }

  // A gate that cannot go red is worse than no gate -- the same rule the Go
  // and shell checkers in this repo follow. This proves the runner, the tag
  // selection and the assertion actually catch the defect class that the
  // notification-preferences toggles, and later the sixteen filter dropdowns,
  // were in.
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
