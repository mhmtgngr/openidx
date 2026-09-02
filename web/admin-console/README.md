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
- **Server-sourced text stays untranslated**: names, descriptions, status
  values, tips/summaries, and error messages that come out of an API
  response render as-is. Only strings authored in the frontend go into the
  catalogs.
- **Page bodies** live under the `pages.*` section, one subsection per
  page. Where a page's `<h1>` is exactly its navigation name, the page
  reuses the `nav.items.*` key instead of duplicating it. Keys referenced
  through runtime maps (e.g. a `Record<status, labelKey>`) are invisible
  to the `typeof en` check — pin them in `src/i18n/i18n.test.ts`.
- **`QueryError`** localizes its own sentences; the `resource` prop is
  interpolated as-is, so pass it already translated
  (`resource={t('pages.sessions.resourceName')}`).
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
