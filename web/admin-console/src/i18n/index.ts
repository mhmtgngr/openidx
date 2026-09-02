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
import tr from './locales/tr'

export const supportedLanguages = [
  { code: 'en', label: 'English' },
  { code: 'tr', label: 'Türkçe' },
] as const

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      tr: { translation: tr },
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

export default i18n
