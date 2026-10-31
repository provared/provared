// ESLint settings for this repository: static analysis that looks for real
// faults, not style. In this folder: "npm ci --ignore-scripts", then
// "npm run lint". Development tools only: nothing here is published.
import security from 'eslint-plugin-security';
import globals from 'globals';

// The folders checked. ESLint is run from the top of the repository with
// this file named by --config, so patterns are read from there. The Python
// folder holds no JavaScript; Ruff checks it (ruff.toml here).
const FOLDERS = ['src', 'bin', 'net', 'page', 'tools', 'integrations', 'gateway', 'sealer', 'conformance'];

// Rules from ESLint's own list that each catch a fault (code that cannot do
// what it seems to), not a matter of style.
const faults = {
  'no-eval': 'error',
  'no-implied-eval': 'error',
  'no-new-func': 'error',
  'no-script-url': 'error',
  'no-caller': 'error',
  'no-with': 'error',
  'no-undef': 'error',
  'no-global-assign': 'error',
  'no-shadow-restricted-names': 'error',
  'no-redeclare': 'error',
  'no-const-assign': 'error',
  'no-func-assign': 'error',
  'no-import-assign': 'error',
  'no-class-assign': 'error',
  'no-dupe-keys': 'error',
  'no-dupe-args': 'error',
  'no-dupe-class-members': 'error',
  'no-dupe-else-if': 'error',
  'no-duplicate-case': 'error',
  'no-fallthrough': 'error',
  'no-unreachable': 'error',
  'no-unsafe-finally': 'error',
  'no-unsafe-negation': 'error',
  'no-unsafe-optional-chaining': 'error',
  'no-self-assign': 'error',
  'no-self-compare': 'error',
  'no-cond-assign': 'error',
  'no-compare-neg-zero': 'error',
  'use-isnan': 'error',
  'valid-typeof': 'error',
  'no-obj-calls': 'error',
  'no-sparse-arrays': 'error',
  'no-loss-of-precision': 'error',
  'no-async-promise-executor': 'error',
  'require-yield': 'error',
  'getter-return': 'error',
  'no-setter-return': 'error',
  'no-constructor-return': 'error',
  'no-invalid-regexp': 'error',
  'no-empty-character-class': 'error',
  'no-misleading-character-class': 'error',
  'no-useless-backreference': 'error',
  'no-template-curly-in-string': 'error',
  'no-unmodified-loop-condition': 'error',
  'no-unused-private-class-members': 'error',
  'no-new-native-nonconstructor': 'error',
  'no-throw-literal': 'error',
  // A weak fingerprint method, or Math.random where a secret is needed.
  'no-restricted-syntax': ['error',
    {
      selector: "CallExpression[callee.property.name=/^create(Hash|Hmac)$/] > Literal:first-child[value=/^(md4|md5|sha1|sha-1|ripemd160)$/i]",
      message: 'A weak fingerprint method (MD4, MD5, SHA-1 or RIPEMD-160). Use SHA-256 or stronger.',
    },
  ],
  'no-restricted-properties': ['error',
    { object: 'Math', property: 'random', message: 'Math.random is not for secrets or identifiers: use crypto.getRandomValues or crypto.randomBytes.' },
  ],
};

// Rules of eslint-plugin-security that look for faults. Left out, each
// because it reports nearly every line that indexes an object or opens a
// file by a computed name, which here are the normal case and checked by
// the code itself: detect-object-injection, detect-non-literal-fs-filename.
const securityRules = {
  'security/detect-eval-with-expression': 'error',
  'security/detect-child-process': 'error',
  'security/detect-unsafe-regex': 'error',
  'security/detect-non-literal-regexp': 'error',
  'security/detect-non-literal-require': 'error',
  'security/detect-new-buffer': 'error',
  'security/detect-buffer-noassert': 'error',
  'security/detect-pseudoRandomBytes': 'error',
  'security/detect-possible-timing-attacks': 'error',
  'security/detect-bidi-characters': 'error',
  'security/detect-disable-mustache-escape': 'error',
  'security/detect-no-csrf-before-method-override': 'error',
};

const configs = [
  {
    ignores: [
      '**/node_modules/**',
      '**/.venv*/**',
      '**/dist/**',
      '**/build/**',
      'provared-check.html',
    ],
  },
  {
    files: FOLDERS.map((f) => `${f}/**/*.{js,mjs,cjs}`),
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      // The library and the pages run both in Node.js and in a browser.
      globals: { ...globals.node, ...globals.browser },
    },
    plugins: { security },
    rules: { ...faults, ...securityRules },
  },
  {
    // Tests are not reached by anyone else's input, and use chance and
    // patterns built from their own fixed text on purpose.
    files: FOLDERS.map((f) => `${f}/**/test/**/*.{js,mjs,cjs}`),
    rules: {
      'no-restricted-properties': 'off',
      'security/detect-non-literal-regexp': 'off',
    },
  },
  {
    files: ['**/*.cjs'],
    languageOptions: { sourceType: 'commonjs' },
  },
];

export default configs;
