// The browser's half of the owner's check (DESIGN.md, section 14.1, X217
// onward): the steps of the setup and of a sign-in, with no page in them.
//
// The executor serves this file to its own pages, as /oauth/owner/steps.js,
// and the tests run it in Node.js. It imports nothing: the two packages
// (@microtoll/crypto-core as "cc", @microtoll/identity as "id"), the passkey
// and the way to reach the executor ("send") are given to it. So the same
// steps run in the browser and in the tests; only the passkey differs.
//
// It calls the packages' own functions only. Nothing here derives, wraps or
// signs by itself.

/** The namespace of every key derivation label (X217). It never changes once an owner exists. */
export const NAMESPACE = 'provared-mcp-executor';

/** The executor's addresses for the owner's check (X218). */
export const OWNER_PATH = '/oauth/owner';
export const LINK_PATH = `${OWNER_PATH}/link`;
export const SETUP_PATH = `${OWNER_PATH}/setup`;
export const PASSKEY_PATH = `${OWNER_PATH}/passkey`;
export const RECOVERY_PATH = `${OWNER_PATH}/recovery`;
export const CHALLENGE_PATH = `${OWNER_PATH}/challenge`;

/** The two fields the authorisation page sends with the owner's answer (X222). */
export const FIELD_CHALLENGE = 'owner_challenge';
export const FIELD_SIGNATURE = 'owner_signature';

/** The name the passkey is made under, and the person's name in it (X225). */
export const RP_NAME = 'provared-mcp-executor';
export const userName = (host) => `Owner of ${host}`;

/**
 * Where a passkey is made (X230): on the device itself, the package's
 * default, or on a phone or a security key. The second is offered where the
 * first fails with one of the package's codes in ELSEWHERE_AFTER: the device
 * gives no PRF, or its prompt was closed or refused.
 */
export const ON_DEVICE = 'platform';
export const ELSEWHERE = 'cross-platform';
export const ELSEWHERE_AFTER = ['prf-unsupported', 'not-allowed'];

/**
 * Make the owner: a new identity, its root key wrapped by the passkey's PRF
 * output and by a new recovery code, and the public half and the two
 * wrapped copies sent to the executor (X219). Gives {recoveryCode}, to be
 * shown once.
 *
 * passkey.create(attachment) -> {credentialId, prfSalt, prfOutput32, transports}
 * send(path, value) -> the executor's JSON answer, or throws
 */
export async function setUp({ cc, id, passkey, code, send, attachment = ON_DEVICE }) {
  // First whether the link still works, so that no passkey is made for a setup the executor would refuse.
  await send(LINK_PATH, { code });
  const made = await passkey.create(attachment);
  const identity = await id.createIdentity(cc);
  const byPasskey = await id.wrapRootKeyWithPrf(cc, identity.rootKey, made.prfOutput32, made.credentialId, made.prfSalt);
  const { method: byCode, displayString } = await id.wrapRootKeyWithNewRecoveryCode(cc, identity.rootKey);
  const b = cc.toBase64Url;
  await send(SETUP_PATH, {
    code,
    routingPublicKey: b(identity.routing.publicKeyRaw),
    // The transports say where the passkey is kept; they go back to the browser at each unlock, so that it asks in the right place (X230).
    passkey: { credentialId: b(byPasskey.credentialId), prfSalt: b(byPasskey.prfSalt), wrappedRootKey: b(byPasskey.wrappedRootKey), transports: [...(made.transports ?? [])] },
    recovery: { salt: b(byCode.salt), lookupHash: byCode.lookupHash, wrappedRootKey: b(byCode.wrappedRootKey) },
  });
  return { recoveryCode: displayString };
}

/**
 * Prove the owner at the authorisation page: open the root key with the
 * passkey's PRF output, or with the recovery code where one is given, then
 * sign the executor's challenge for this request with the routing key
 * (X221, X222). "request" is the form's request field. Gives the fields the
 * page puts in the form: the request with its challenge sealed in, in place
 * of the one it had, and the check's two.
 *
 * passkey.evaluate(credentialId, prfSalt, transports) -> {prfOutput32}
 */
export async function signIn({ cc, id, passkey, recoveryCode = '', request, origin, send }) {
  const f = cc.fromBase64Url;
  let rootKey;
  if (recoveryCode.trim() !== '') {
    const lookupHash = await id.lookupHashForEnteredCode(cc, recoveryCode);
    const m = await send(RECOVERY_PATH, { lookupHash });
    rootKey = await id.unwrapRootKeyWithRecoveryCode(cc, { type: id.METHOD_RECOVERY, label: null, wrappedRootKey: f(m.wrappedRootKey), salt: f(m.salt), lookupHash: m.lookupHash }, recoveryCode);
  } else {
    const m = await send(PASSKEY_PATH, {});
    const method = { type: id.METHOD_PASSKEY, label: null, wrappedRootKey: f(m.wrappedRootKey), credentialId: f(m.credentialId), prfSalt: f(m.prfSalt) };
    const { prfOutput32 } = await passkey.evaluate(method.credentialId, method.prfSalt, Array.isArray(m.transports) ? m.transports : []);
    rootKey = await id.unwrapRootKeyWithPrf(cc, method, prfOutput32);
  }
  const identity = await id.identityFromRootKey(cc, rootKey);
  // The challenge is asked for last, so that its two minutes are not spent at the passkey.
  const { challenge, request: withChallenge } = await send(CHALLENGE_PATH, { request });
  const signature = await cc.signBytes(identity.routing.privateKey, await id.authMessage(cc, origin, f(challenge)));
  return { request: withChallenge, [FIELD_CHALLENGE]: challenge, [FIELD_SIGNATURE]: cc.toBase64Url(signature) };
}
