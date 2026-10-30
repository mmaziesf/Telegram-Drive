// @ts-check
import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

/**
 * Lint configuration for the React/TypeScript frontend.
 *
 * Type checking is done separately by `tsc --noEmit`; this config
 * enforces correctness rules that the compiler does not cover.
 */
export default tseslint.config(
    { ignores: ['dist', 'node_modules', 'src-tauri', 'test-results', 'playwright-report'] },
    {
        files: ['**/*.{ts,tsx}'],
        extends: [js.configs.recommended, ...tseslint.configs.recommended],
        languageOptions: {
            ecmaVersion: 2022,
            globals: { ...globals.browser, ...globals.node },
        },
        plugins: { 'react-hooks': reactHooks },
        rules: {
            'react-hooks/rules-of-hooks': 'error',
            // Intentionally unused parameters and bindings are prefixed with `_`.
            '@typescript-eslint/no-unused-vars': ['error', {
                argsIgnorePattern: '^_',
                varsIgnorePattern: '^_',
            }],
            // Best-effort browser APIs (storage, media playback) may throw;
            // an empty catch documents that the failure is deliberately ignored.
            'no-empty': ['error', { allowEmptyCatch: true }],
            // Not yet enforced repo-wide. Tests still use `any`
            // (product code is enforced below), and 43 hook
            // dependency lists are incomplete. Changing hook dependencies can
            // alter effect timing, so each one needs its own reviewed change.
            // These rules stay off until that cleanup is done.
            '@typescript-eslint/no-explicit-any': 'off',
            'react-hooks/exhaustive-deps': 'off',
        },
    },
    {
        // Product code is free of `any`; keep it that way.
        files: ['src/**/*.{ts,tsx}'],
        rules: { '@typescript-eslint/no-explicit-any': 'error' },
    },
);
