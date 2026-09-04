// i18n bootstrap for the admin console.
//
// Conventions (the landing page is the reference extraction):
//   - English (en.ts) is the source of truth; other locales are typed
//     against it, so key drift fails `npm run type-check`.
//   - Components use `useTranslation()` and t('landing.hero.badge') keys.
//   - The chosen language persists in localStorage ('openidx.lang') and is
//     otherwise detected from the browser; English is the fallback.
//   - Proper nouns (product names, protocol names) stay untranslated.
//
// Import this module once from main.tsx (and from the vitest setup file so
// component tests render with the same singleton).
import i18n from 'i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import { initReactI18next } from 'react-i18next'

import en from './locales/en'

export const supportedLanguages = [
  { code: 'en', label: 'English' },
  { code: 'tr', label: 'Türkçe' },
] as const

// Only English is bundled with the entry chunk. The catalogs are 360 KB of
// source EACH, and shipping every language to every reader means an English
// reader downloads and parses a Turkish catalog they will never render before
// the first paint. Each additional locale is a dynamic import, so it costs one
// chunk fetched on demand.
//
// The type is still checked at build time: locales/tr.ts declares
// `const tr: typeof en`, and `import type` carries no runtime cost, so a key
// added to en.ts and not translated still fails `npm run type-check`.
const lazyCatalogs: Record<string, () => Promise<{ default: typeof en }>> = {
  tr: () => import('./locales/tr'),
}

/** Loads a locale's catalog if it is not already in memory. */
export async function ensureLanguage(code: string): Promise<void> {
  const load = lazyCatalogs[code]
  if (!load || i18n.hasResourceBundle(code, 'translation')) return
  const mod = await load()
  i18n.addResourceBundle(code, 'translation', mod.default, true, true)
}

/**
 * Switches language, fetching the catalog first.
 *
 * Everything that changes language must go through this rather than
 * i18n.changeLanguage: switching to a locale whose bundle has not arrived
 * leaves i18next falling back to English with no error, which looks like a
 * missing translation rather than a missing fetch.
 */
export async function setLanguage(code: string): Promise<void> {
  await ensureLanguage(code)
  await i18n.changeLanguage(code)
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
    },
    fallbackLng: 'en',
    supportedLngs: supportedLanguages.map((l) => l.code),
    interpolation: {
      // React already escapes rendered strings.
      escapeValue: false,
    },
    detection: {
      order: ['localStorage', 'navigator'],
      caches: ['localStorage'],
      lookupLocalStorage: 'openidx.lang',
    },
  })

// The detector has already chosen a language by now; if it is a lazy one the
// first paint is English and this swaps it in as soon as the chunk lands.
// Deliberately not awaited: blocking module evaluation on a fetch would block
// the app shell too.
const detected = i18n.resolvedLanguage ?? i18n.language
if (detected && detected !== 'en') {
  void setLanguage(detected)
}

export default i18n
