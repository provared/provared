// Loaded first (with --import) by test-files.test.mjs: from here on the name
// "provared" is not found in node_modules, as on a clean checkout, where
// nothing is installed. Only local-library.mjs, registered after this file
// and so asked before it, can then resolve the name.

import { registerHooks } from 'node:module';

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'provared' || specifier.startsWith('provared/')) {
      throw Object.assign(new Error(`Cannot find package '${specifier}': nothing is installed (a clean checkout).`), { code: 'ERR_MODULE_NOT_FOUND' });
    }
    return nextResolve(specifier, context);
  },
});
