// Records of this reader's own, in AMW's published shape, signed with a key
// made for the tests: a gateway key list, permits and receipts. Only the
// shape is AMW's; every value is invented. (No AMW program was read: the
// shape is taken from the published test data under vectors/.)

import { generateKeyPairSync, sign } from 'node:crypto';

/** A gateway with one Ed25519 key, "sk_test_0001", active. */
export function makeGateway(kid = 'sk_test_0001', status = 'active') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const x = publicKey.export({ format: 'jwk' }).x;
  const raw = Buffer.from(x, 'base64url');
  const entry = { kid, alg: 'Ed25519', status, public_key_b64: raw.toString('base64'), jwk: { kty: 'OKP', crv: 'Ed25519', x } };
  return { kid, privateKey, entry, keys: { keys: [entry] } };
}

// AMW signs the content as JSON with its members in sorted order and no
// white space. The exact text is what the signature covers, so the text
// is kept in the envelope as "signing_input".
function sortedJson(value) {
  if (Array.isArray(value)) return `[${value.map(sortedJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${sortedJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * Sign a receipt's content and wrap it as AMW's envelope.
 * @param {ReturnType<typeof makeGateway>} gateway
 * @param {object} fields the content, without "alg" and "kid"
 */
export function signReceipt(gateway, fields) {
  const content = { alg: 'Ed25519', kid: gateway.kid, ...fields };
  const signing_input = sortedJson(content);
  const signature = sign(null, Buffer.from(signing_input, 'utf8'), gateway.privateKey).toString('base64');
  return { receipt_id: content.receipt_id, kid: gateway.kid, alg: 'Ed25519', canonicalization: 'awi-canonical-json/1', signing_input, signature };
}

/** As signReceipt, for a permit (its envelope has no "canonicalization"). */
export function signPermit(gateway, fields) {
  const content = { alg: 'Ed25519', kid: gateway.kid, status: 'active', ...fields };
  const signing_input = sortedJson(content);
  const signature = sign(null, Buffer.from(signing_input, 'utf8'), gateway.privateKey).toString('base64');
  return { permit_id: content.permit_id, kid: gateway.kid, alg: 'Ed25519', signing_input, signature };
}

let counter = 0;

/** A receipt of a successful call, with the fields AMW's receipts carry; "more" overrides any of them. */
export function receipt(gateway, more = {}) {
  counter += 1;
  const n = String(counter).padStart(4, '0');
  return signReceipt(gateway, {
    receipt_id: `rcpt_test_${n}`,
    permit_id: 'pmt_test_0001',
    tool: 'echo',
    outcome: 'success',
    credits_authorized: '2.5',
    credits_charged: '2.5',
    created_at: '2026-09-14T17:00:00+00:00',
    wallet_id: 'agt-test-subject',
    key_id: 'key_test_0001',
    request_hash: 'a'.repeat(64),
    response_hash: 'b'.repeat(64),
    ledger_entry_id: `led_test_${n}`,
    audit_event_id: `aud_test_${n}`,
    payload_hash: '0'.repeat(64),
    ...more,
  });
}

/** A permit in AMW's shape; "more" overrides any field. */
export function permit(gateway, more = {}) {
  return signPermit(gateway, {
    permit_id: 'pmt_test_0001',
    issuer_wallet_id: 'agt-test-issuer',
    subject_wallet_id: 'agt-test-subject',
    subject_key_id: 'key_test_0001',
    allowed_tools: ['echo'],
    scopes: ['tool:echo:invoke'],
    max_credits: '50',
    issued_at: '2026-09-14T12:00:00+00:00',
    expires_at: '2026-09-15T12:00:00+00:00',
    nonce: 'nonce_test_0001',
    payload_hash: '0'.repeat(64),
    ...more,
  });
}
