// For tests: a library release that has no client for a time-stamp
// service. Loaded with --import after the package's local-library.mjs, it
// makes "provared/net/timestamp" fail to resolve, as it does under a
// release before the one that has it.

import { registerHooks } from 'node:module';

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'provared/net/timestamp') {
      throw Object.assign(new Error('Package subpath \'./net/timestamp\' is not defined by "exports" (a test hides it).'), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
    }
    return nextResolve(specifier, context);
  },
});
