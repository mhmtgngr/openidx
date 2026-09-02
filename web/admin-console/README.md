# OpenIDX Admin Console

React + TypeScript (Vite) console for the OpenIDX platform.

```bash
npm install
npm run dev         # Vite dev server
npm run test        # vitest
npm run lint        # eslint
npm run type-check  # tsc -b
npm run build       # production build (tsc -b && vite build)
```

## Internationalization (i18n)

The console uses [i18next](https://www.i18next.com/) with `react-i18next`.
The landing page (`src/pages/landing.tsx`) is the reference extraction —
copy its pattern when extracting a page.

Conventions:

- **English is the source of truth**: `src/i18n/locales/en.ts`. Every other
  locale is typed against it (`const tr: typeof en = { ... }`), so a
  missing or extra key fails `npm run type-check` — there is no way to ship
  a half-translated catalog silently.
- **Components** call `useTranslation()` and reference dotted keys
  (`t('landing.hero.badge')`). Interpolation uses i18next syntax:
  `t('landing.footer.copyright', { year })` with `{{year}}` in the catalog.
- **Language choice** persists in `localStorage` under `openidx.lang`
  (falling back to browser language, then English). The
  `LanguageSwitcher` component (`src/components/language-switcher.tsx`)
  changes it live.
- **Proper nouns stay untranslated**: product names (Okta, Slack),
  protocol names (SAML, OIDC, SCIM), and the OpenIDX name itself.
- **Tests** render with the same i18n singleton (initialized from
  `src/test/setup.ts`), in English — assert English strings, and restore
  `en` if a test changes the language.

To add a language: add its catalog under `src/i18n/locales/`, typed
`typeof en`; register it in the `resources` map and `supportedLanguages`
list in `src/i18n/index.ts`. Type-check enforces completeness.

## Truthful marketing surfaces

The public-facing pages (landing) state **verifiable facts only** — no
invented SLAs, trials, pricing, latency figures, or adoption numbers. A
regression test (`src/pages/landing.test.tsx`, "makes no claims a
self-hosted OSS project cannot keep") pins this.
