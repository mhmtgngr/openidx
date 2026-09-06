import { describe, it, expect } from 'vitest'
// `?raw` gives the stylesheet as a string without processing it as CSS, and
// without pulling node path/fs types into a browser-targeted tsconfig.
import CSS from '../index.css?raw'

// Contrast guard for the DESIGN TOKENS, in both themes.
//
// The console has two other contrast checks and this one covers what neither
// can:
//
//   - The jsdom axe gate (a11y.test.tsx) disables color-contrast outright:
//     jsdom has no layout or paint, so the rule cannot run there at all.
//   - A headless-browser sweep can only judge the pairings that happen to be
//     on screen. It found and fixed real failures, but it never rendered a
//     destructive button -- those live inside confirm dialogs -- so it could
//     not see that the Delete / Revoke / Terminate label was 3.59:1 in the
//     light theme. This test reads the tokens straight out of index.css, so a
//     pair is checked whether or not any route happens to paint it, and it
//     runs in CI with no browser and no server.
//
// What it does NOT cover: pairings built from Tailwind palette utilities
// (`text-red-500` on `bg-muted`, tinted surfaces like `bg-blue-50/50` that
// composite differently per theme). Those need the browser sweep. This is the
// token layer only -- but the token layer is where a single wrong value goes
// wrong on every page at once, which is exactly what happened to
// --muted-foreground and to --primary.

/** `H S% L%` as Tailwind/shadcn write it, e.g. `222.2 84% 4.9%`. */
function parseTheme(selector: string): Record<string, [number, number, number]> {
  // Each theme block ends at the first line that closes it at two-space indent.
  const start = CSS.indexOf(selector + ' {')
  if (start === -1) throw new Error(`no ${selector} block in index.css`)
  const end = CSS.indexOf('\n  }', start)
  if (end === -1) throw new Error(`unterminated ${selector} block in index.css`)
  const body = CSS.slice(start, end)

  const out: Record<string, [number, number, number]> = {}
  const re = /--([a-z-]+):\s*([\d.]+)\s+([\d.]+)%\s+([\d.]+)%\s*;/g
  let m: RegExpExecArray | null
  while ((m = re.exec(body)) !== null) {
    out[m[1]] = [Number(m[2]), Number(m[3]), Number(m[4])]
  }
  return out
}

function hslToRgb([h, s, l]: [number, number, number]): [number, number, number] {
  const sn = s / 100
  const ln = l / 100
  const c = (1 - Math.abs(2 * ln - 1)) * sn
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1))
  const m = ln - c / 2
  const seg = Math.floor(h / 60) % 6
  const [r, g, b] = (
    [
      [c, x, 0],
      [x, c, 0],
      [0, c, x],
      [0, x, c],
      [x, 0, c],
      [c, 0, x],
    ] as const
  )[seg]
  return [(r + m) * 255, (g + m) * 255, (b + m) * 255]
}

/** WCAG 2.1 relative luminance. */
function luminance(rgb: [number, number, number]): number {
  const [r, g, b] = rgb.map((v) => {
    const c = v / 255
    return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)
  })
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

export function contrast(
  a: [number, number, number],
  b: [number, number, number]
): number {
  const la = luminance(hslToRgb(a))
  const lb = luminance(hslToRgb(b))
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}

// Every pair here is one the app actually renders: a foreground token the
// components put on a surface token. Adding a token to index.css does not
// automatically add it here -- but a token whose VALUE drifts under AA in a
// pairing already listed will turn this red, which is the regression this
// guards against.
const PAIRS: Array<[fg: string, bg: string, why: string]> = [
  ['foreground', 'background', 'body text on the page'],
  ['foreground', 'card', 'body text inside a card'],
  ['card-foreground', 'card', 'card body text'],
  ['popover-foreground', 'popover', 'dropdown and popover text'],
  ['muted-foreground', 'background', 'secondary copy on the page'],
  ['muted-foreground', 'card', 'secondary copy in a card'],
  ['muted-foreground', 'muted', 'secondary copy on a muted strip'],
  ['primary', 'background', 'links and primary-coloured text'],
  ['primary', 'card', 'primary-coloured text in a card'],
  ['primary', 'muted', 'primary-coloured links on a muted strip'],
  ['primary-foreground', 'primary', 'the label of a primary button'],
  ['secondary-foreground', 'secondary', 'the label of a secondary button'],
  ['accent-foreground', 'accent', 'text on a hovered/selected row'],
  [
    'destructive-foreground',
    'destructive',
    'the label of a Delete / Revoke / Terminate button',
  ],
]

const AA_NORMAL = 4.5

describe('design tokens meet WCAG AA in both themes', () => {
  for (const [selector, theme] of [
    [':root', 'light'],
    ['.dark', 'dark'],
  ] as const) {
    describe(theme, () => {
      const tokens = parseTheme(selector)

      for (const [fg, bg, why] of PAIRS) {
        it(`${fg} on ${bg} (${why})`, () => {
          // A pair naming a token that no longer exists is a failure, not a
          // skip: silently dropping it is how a guard rots into a no-op.
          expect(tokens[fg], `--${fg} missing from ${selector}`).toBeDefined()
          expect(tokens[bg], `--${bg} missing from ${selector}`).toBeDefined()

          const ratio = contrast(tokens[fg], tokens[bg])
          expect(
            Number(ratio.toFixed(2)),
            `--${fg} on --${bg} in ${theme} is ${ratio.toFixed(2)}:1, ` +
              `under AA's ${AA_NORMAL}:1 for normal text (${why})`
          ).toBeGreaterThanOrEqual(AA_NORMAL)
        })
      }
    })
  }

  // A guard that cannot go red is worse than no guard -- the rule every other
  // checker in this repo follows. These pin the maths itself, so a broken
  // parser or a sign error cannot make the suite above pass vacuously.
  it('goes red on a pair that fails', () => {
    // #ef4444-ish on white: 3.76:1, the value --destructive used to have.
    expect(contrast([0, 84.2, 60.2], [0, 0, 100])).toBeLessThan(AA_NORMAL)
  })

  it('agrees with known WCAG reference ratios', () => {
    // Black on white is exactly 21:1; a colour against itself is exactly 1:1.
    expect(contrast([0, 0, 0], [0, 0, 100])).toBeCloseTo(21, 5)
    expect(contrast([210, 40, 98], [210, 40, 98])).toBeCloseTo(1, 5)
  })

  it('actually parsed both themes', () => {
    // If the block regex silently matched nothing, every pair above would
    // fail on "missing" rather than on contrast -- but a future refactor of
    // index.css could also leave one block empty and the other full.
    expect(Object.keys(parseTheme(':root')).length).toBeGreaterThan(10)
    expect(Object.keys(parseTheme('.dark')).length).toBeGreaterThan(10)
  })
})
