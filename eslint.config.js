// Lint configuration (npm run lint): ESLint's recommended rules, for the
// server and tests (CommonJS, Node) and the front end (ES modules, browser).
// Globals are listed here rather than taken from a package, to keep the
// development dependencies to ESLint alone.
'use strict';

const js = require('@eslint/js');

const node = { require: 'readonly', module: 'writable', process: 'readonly', __dirname: 'readonly', __filename: 'readonly', console: 'readonly', Buffer: 'readonly', setTimeout: 'readonly', clearTimeout: 'readonly', URL: 'readonly', URLSearchParams: 'readonly', fetch: 'readonly', AbortSignal: 'readonly', setInterval: 'readonly', FormData: 'readonly', Blob: 'readonly', TextDecoder: 'readonly', Headers: 'readonly', globalThis: 'readonly' };
const browser = { window: 'readonly', document: 'readonly', location: 'readonly', history: 'readonly', fetch: 'readonly', URL: 'readonly', URLSearchParams: 'readonly', Blob: 'readonly', FormData: 'readonly', confirm: 'readonly', console: 'readonly', setTimeout: 'readonly', clearTimeout: 'readonly', ResizeObserver: 'readonly', performance: 'readonly', requestAnimationFrame: 'readonly' };
const rules = {
  ...js.configs.recommended.rules,
  'no-unused-vars': ['error', { args: 'after-used', argsIgnorePattern: '^_', caughtErrors: 'none' }],
  eqeqeq: ['error', 'always', { null: 'ignore' }],
  'prefer-const': 'error',
  'no-var': 'error',
};

module.exports = [
  { ignores: ['node_modules/', 'data/', 'test/fixtures/'] },
  { files: ['**/*.js'], languageOptions: { ecmaVersion: 2024, sourceType: 'commonjs', globals: node }, rules },
  { files: ['public/js/**/*.js'], languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: browser }, rules },
];
