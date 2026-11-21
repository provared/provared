// The browser's half of the owner's check (DESIGN.md, section 14.1, X270
// onward): the steps of the setup and of an approval, with no page in them.
//
// The executor serves this file to its own pages, as /oauth/owner/steps.js,
// and the tests run it in Node.js. It imports nothing: the passkey, the way
// to reach the executor ("send") and the way to write bytes as base64url
// ("encode") are given to it. So the same steps run in the browser and in
// the tests; only the passkey differs.
//
// Nothing here signs, hashes or checks by itself.

/** The executor's addresses for the owner's check (X218, X271, X273). */
export const OWNER_PATH = '/oauth/owner';
export const LINK_PATH = `${OWNER_PATH}/link`;
export const SETUP_PATH = `${OWNER_PATH}/setup`;
export const CHALLENGE_PATH = `${OWNER_PATH}/challenge`;

/** The fields the authorisation page sends with the owner's answer (X274): the challenge and the passkey's three values, or the recovery code. */
export const FIELD_CHALLENGE = 'owner_challenge';
export const FIELD_AUTHENTICATOR_DATA = 'owner_authenticator_data';
export const FIELD_CLIENT_DATA = 'owner_client_data';
export const FIELD_SIGNATURE = 'owner_signature';
export const FIELD_RECOVERY = 'owner_recovery';

/** The name the passkey is made under, and the person's name in it (X225). */
export const RP_NAME = 'provared-mcp-executor';
export const userName = (host) => `Owner of ${host}`;

/** What the pages keep in the browser's storage for the executor's address, so that the setup and the first approval take one prompt (X272): the setup link's code, and the request of a page that waits where no owner exists. */
export const STORE_CODE = 'provared-owner-setup-code';
export const STORE_WAITING = 'provared-owner-waiting-request';

/**
 * Make the owner: a new passkey, whose identifier and public key go to the
 * executor with the setup link's code (X271). With "request", the request of
 * an authorisation page that waits, the same message approves that one
 * request (X272). Gives the executor's answer: {owner: 'set', recoveryCode},
 * the code to be shown once, and with a request {request}: that request
 * approved, for the page's form, or null where it had ended.
 *
 * passkey.create() -> {credentialId, key}: the identifier in base64url and the public key as a JWK
 * send(path, value) -> the executor's JSON answer, or throws
 */
export async function setUp({ passkey, code, request = null, send }) {
  // First whether the link still works, so that no passkey is made for a setup the executor would refuse.
  await send(LINK_PATH, { code });
  const made = await passkey.create();
  return send(SETUP_PATH, { code, credentialId: made.credentialId, key: made.key, ...(request === null ? {} : { request }) });
}

/**
 * Prove the owner at the authorisation page: ask the executor for a
 * challenge for this request, and have the passkey sign it (X273, X274).
 * "request" is the form's request field. Gives the fields the page puts in
 * the form: the request with its challenge sealed in, in place of the one
 * it had, and the check's four.
 *
 * passkey.sign(credentialId, challenge) -> {authenticatorData, clientDataJSON, signature}, as bytes; "challenge" is the executor's, in base64url
 * encode(bytes) -> base64url
 */
export async function signIn({ passkey, request, send, encode }) {
  const given = await send(CHALLENGE_PATH, { request });
  const signed = await passkey.sign(given.credentialId, given.challenge);
  return {
    request: given.request,
    [FIELD_CHALLENGE]: given.challenge,
    [FIELD_AUTHENTICATOR_DATA]: encode(signed.authenticatorData),
    [FIELD_CLIENT_DATA]: encode(signed.clientDataJSON),
    [FIELD_SIGNATURE]: encode(signed.signature),
  };
}
