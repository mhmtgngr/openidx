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
  // Markup the console did not write never becomes part of its document.
  // There it runs with the console's origin, which holds the access and
  // refresh tokens: the email-template preview put an administrator's HTML
  // into the page this way, and every administrator who opened it ran that
  // HTML's script. HTML from anyone else goes in an <iframe srcDoc> whose
  // sandbox allows no script (components/email-preview-frame.tsx). Errors,
  // not warnings, because one of these is a vulnerability rather than debt.
  // Tests are exempt: they reset the document with innerHTML.
  {
    files: ['src/**/*.{ts,tsx}'],
    ignores: ['src/**/*.test.{ts,tsx}', 'src/test/**'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: 'Render HTML you did not write in an <iframe srcDoc sandbox="">, not in the console document.',
        },
        {
          selector: 'AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]',
          message: 'Assigning HTML puts it in the console document; build nodes, set textContent, or use a sandboxed srcDoc frame.',
        },
        {
          selector: 'CallExpression[callee.property.name=/^(insertAdjacentHTML|createContextualFragment|setHTMLUnsafe)$/]',
          message: 'This parses HTML into the console document; use a sandboxed srcDoc frame.',
        },
        {
          selector: "CallExpression[callee.object.name='document'][callee.property.name=/^(write|writeln)$/]",
          message: 'document.write parses HTML into the console document.',
        },
        {
          selector: "JSXOpeningElement[name.name='iframe']:has(JSXAttribute[name.name='srcDoc']):not(:has(JSXAttribute[name.name='sandbox']))",
          message: 'A srcDoc frame without sandbox shares the console origin; add sandbox="" (no allow-scripts, no allow-same-origin).',
        },
        {
          selector: "JSXAttribute[name.name='sandbox'][value.value=/allow-scripts/][value.value=/allow-same-origin/]",
          message: 'allow-scripts with allow-same-origin lets the framed document remove its own sandbox.',
        },
      ],
    },
  },
)
