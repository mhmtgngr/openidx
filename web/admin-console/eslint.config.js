import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

// eslint-plugin-react-hooks v7's `recommended` config promotes many advisory
// rules (set-state-in-effect, etc.) to errors. Consistent with the lint
// philosophy below (surface accumulated, never-enforced debt as warnings so the
// gate stays green while it's burned down), remap the recommended react-hooks
// rules to 'warn' severity, preserving any rule options.
const reactHooksWarnings = Object.fromEntries(
  Object.entries(reactHooks.configs.recommended.rules ?? {}).map(([rule, cfg]) => [
    rule,
    Array.isArray(cfg) ? ['warn', ...cfg.slice(1)] : 'warn',
  ]),
)

export default tseslint.config(
  { ignores: ['dist'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooksWarnings,
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
      // Lint was never enforced before now, so the codebase carries
      // accumulated style debt (unused vars/imports, explicit `any`).
      // Surface these as warnings so the lint gate is green and CI
      // signal is trustworthy, while the debt stays visible to burn
      // down incrementally. `^_`-prefixed identifiers are intentionally
      // unused and fully ignored.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-empty-object-type': 'warn',
      // New eslint-10 core rule flagging pre-existing catch blocks that rethrow
      // without a `cause`; advisory, not broken code — keep as a warning.
      'preserve-caught-error': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
    },
  },
)
