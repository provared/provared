// One warning set aside: Node.js's notice that its ML-DSA-87 signing is
// experimental. The executor signs every receipt with ML-DSA-87 beside
// Ed25519, so Node.js prints that notice on every run of the command, where
// it reads like an error. Only that notice is set aside, and only in the
// command (bin.mjs imports this file first); every other warning is
// printed as Node.js prints it. The library, used by itself, sets nothing
// aside.

/** Whether a warning is Node.js's notice that ML-DSA-87 is experimental, and nothing else. */
export function isMlDsaNotice(warning, type) {
  const name = typeof type === 'string' ? type : typeof type?.type === 'string' ? type.type : warning?.name;
  const text = typeof warning === 'string' ? warning : warning?.message;
  return name === 'ExperimentalWarning' && typeof text === 'string' && text.startsWith('The ML-DSA-87 Web Crypto API algorithm is an experimental feature');
}

const emitWarning = process.emitWarning;
process.emitWarning = function (warning, type, ...rest) {
  if (isMlDsaNotice(warning, type)) return;
  return emitWarning.call(this, warning, type, ...rest);
};
