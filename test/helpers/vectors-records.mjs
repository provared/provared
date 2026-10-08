// Shared test cases for the approval, the refusal, a service's terms, the
// cancellation, the acknowledgement, the vouching record, the withdrawal
// and the pass.
//
// The keys in the cases have the right shapes and made-up values: the
// checks of content look only at shapes. Where a record is written, its
// Ed25519 key is fixed by the case, so that the record, its fingerprint and
// its Ed25519 signature are the same in every implementation. Its ML-DSA-87
// key is made afresh, because an ML-DSA-87 signature differs each time; the
// answer then says only whether that signature checks.

import { assembleApproval, prepareApproval, requestOf, validateApprovalContent } from '../../src/approval.js';
import { fromBase64url, toBase64url } from '../../src/encoding.js';
import { protectedHeaders, signingInput } from '../../src/jws.js';
import { MAX_PASSES, validatePassContent, writePass } from '../../src/pass.js';
import { REFUSAL_REASONS, validateRefusalContent, validateTermsContent, writeRefusal, writeTerms } from '../../src/service.js';
import { verifySignature } from '../../src/signatures.js';
import {
  VOUCHED_KINDS,
  assembleCancellation,
  prepareCancellation,
  validateAcknowledgementContent,
  validateCancellationContent,
  validateVouchingContent,
  validateWithdrawalContent,
  writeAcknowledgement,
  writeVouching,
  writeWithdrawal,
} from '../../src/standing.js';
import { answer, finish } from './vector-tools.mjs';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const bytes = (text) => Uint8Array.from(Buffer.from(text, 'hex'));

/** A content check: true, or why it was refused. */
const valid = (check) => (c) =>
  answer(() => {
    check(c.content);
    return true;
  });

/** What a passkey record's preparation gives, with its bytes in hexadecimal. */
const prepared = (prepare) => (c) =>
  answer(async () => {
    const p = await prepare(c.fields);
    return { contentBytes: hex(p.contentBytes), payloadB64: p.payloadB64, protectedB64: p.protectedB64, challenge: hex(p.challenge), fingerprint: p.fingerprint };
  });

/** A passkey record put together from a preparation and the passkey's three values. */
const assembled = (assemble) => (c) =>
  answer(() =>
    assemble(c.prepared, { authenticatorData: bytes(c.authenticatorData), clientDataJSON: bytes(c.clientDataJSON), signature: bytes(c.signature) }),
  );

// The fixed start of the PKCS #8 form of an Ed25519 private key (RFC 8410),
// before its 32 bytes.
const ED25519_PKCS8 = '302e020100300506032b657004220420';

/**
 * A record written and signed: its content, its fingerprint and its Ed25519
 * signature exactly, and whether its ML-DSA-87 signature checks.
 */
const written = (write) => (c) =>
  answer(async () => {
    const subtle = globalThis.crypto.subtle;
    const ed = await subtle.importKey('pkcs8', bytes(ED25519_PKCS8 + c.seed), { name: 'Ed25519' }, false, ['sign']);
    const ml = await subtle.generateKey({ name: 'ML-DSA-87' }, false, ['sign', 'verify']);
    const { pub } = await subtle.exportKey('jwk', ml.publicKey);
    const { record, fingerprint } = await write(c.fields, [ed, ml.privateKey]);
    const [first, second] = record.signatures;
    const check = await verifySignature({ alg: 'ML-DSA-87', kty: 'AKP', pub }, fromBase64url(second.signature), signingInput(second.protected, record.payload));
    return { fingerprint, payload: record.payload, signatures: [first, { protected: second.protected, check }] };
  });

/** How each kind of case is answered. */
export const ANSWER = {
  validateApprovalContent: valid(validateApprovalContent),
  requestOf: (c) => answer(() => requestOf(c.content)),
  prepareApproval: prepared(prepareApproval),
  assembleApproval: assembled(assembleApproval),
  validateRefusalContent: valid(validateRefusalContent),
  validateTermsContent: valid(validateTermsContent),
  writeRefusal: written(writeRefusal),
  writeTerms: written(writeTerms),
  validateCancellationContent: valid(validateCancellationContent),
  validateAcknowledgementContent: valid(validateAcknowledgementContent),
  validateVouchingContent: valid(validateVouchingContent),
  validateWithdrawalContent: valid(validateWithdrawalContent),
  prepareCancellation: prepared(prepareCancellation),
  assembleCancellation: assembled(assembleCancellation),
  writeAcknowledgement: written(writeAcknowledgement),
  writeVouching: written(writeVouching),
  writeWithdrawal: written(writeWithdrawal),
  validatePassContent: valid(validatePassContent),
  writePass: written(writePass),
  recordConstants: () => answer(() => ({ REFUSAL_REASONS, VOUCHED_KINDS, MAX_PASSES })),
};

// --- values the cases share ---

const b64 = (length, fill) => toBase64url(new Uint8Array(length).fill(fill));
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/** The same text with its last character one further on: bits that must be zero are no longer. */
const stray = (text) => text.slice(0, -1) + ALPHABET[ALPHABET.indexOf(text.at(-1)) + 1];

const FP = b64(32, 1);
const FP2 = b64(32, 3);
const ID = b64(16, 2);
const WHEN = '2026-10-05T09:00:00Z';
const FROM = '2026-10-05T08:00:00Z';
const UNTIL = '2026-10-12T08:00:00Z';
const T = Date.UTC(2026, 9, 5, 9); // WHEN, in milliseconds since 1970
const SEED = '07'.repeat(32);

const ED = { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: b64(32, 4) };
const ML = { alg: 'ML-DSA-87', kty: 'AKP', pub: b64(2592, 5) };
const SLH = { alg: 'SLH-DSA-SHA2-256s', kty: 'AKP', pub: b64(64, 6) };
const ES = { alg: 'ES256', crv: 'P-256', kty: 'EC', x: b64(32, 7), y: b64(32, 8) };
const RS = { alg: 'RS256', e: 'AQAB', kty: 'RSA', n: b64(256, 0xc1) };
const KEY_SET = [ED, ML];
const SEAL_SET = [ED, ML, SLH];
const BY = { name: 'Example Stationery (invented)', keys: KEY_SET };
const DOC = { name: 'order.pdf', sha256: FP2 };

/** The same object with one member, perhaps inside another, put in place. */
function put(object, path, value) {
  const [head, ...rest] = path.split('.');
  return { ...object, [head]: rest.length ? put(object[head], rest.join('.'), value) : value };
}

/** The same object without one member, perhaps inside another. */
function drop(object, path) {
  const [head, ...rest] = path.split('.');
  if (rest.length) return { ...object, [head]: drop(object[head], rest.join('.')) };
  const { [head]: _, ...others } = object;
  return others;
}

/** The same object with a member named __proto__, written as a member of its own. */
function withProto(object) {
  const copy = { ...object };
  Object.defineProperty(copy, '__proto__', { value: 1, enumerable: true, writable: true, configurable: true });
  return copy;
}

/** Cases that change one member: [name, content]. */
const each = (base, path, values) => values.map(([name, value]) => [`${path}: ${name}`, put(base, path, value)]);

/** Cases that leave out each member in turn. */
const missing = (base, names, path = '') => names.map((name) => [`no ${path ? path + '.' : ''}${name}`, drop(base, path ? `${path}.${name}` : name)]);

/** Values that are not content at all. */
const NOT_OBJECTS = [
  ['a list', [{}]],
  ['null', null],
  ['text', 'content'],
  ['a number', 1],
  ['true', true],
  ['an empty object', {}],
];

const IDS = [
  ['16 bytes', ID],
  ['15 bytes', b64(15, 2)],
  ['17 bytes', b64(17, 2)],
  ['32 bytes', FP],
  ['padding', ID + '=='],
  ['a plus sign', ID.slice(0, -2) + '+g'],
  ['stray bits', stray(ID)],
  ['an impossible length', 'A'],
  ['empty text', ''],
  ['a number', 1],
  ['null', null],
  ['a list', [ID]],
];

const FINGERPRINTS = [
  ['32 bytes', FP],
  ['31 bytes', b64(31, 1)],
  ['33 bytes', b64(33, 1)],
  ['16 bytes', ID],
  ['padding', FP + '='],
  ['a slash', FP.slice(0, -2) + '/A'],
  ['stray bits', stray(FP)],
  ['empty text', ''],
  ['a number', 1],
  ['null', null],
  ['true', true],
];

const TIMES = [
  ['a time', WHEN],
  ['a leap day', '2024-02-29T00:00:00Z'],
  ['the year 0', '0000-01-01T00:00:00Z'],
  ['the last second of the year 9999', '9999-12-31T23:59:59Z'],
  ['before 1970', '1969-12-31T23:59:59Z'],
  ['a fraction of a second', '2026-10-05T09:00:00.000Z'],
  ['an offset', '2026-10-05T09:00:00+01:00'],
  ['30 February', '2026-02-30T09:00:00Z'],
  ['29 February in a year that is not a leap year', '2026-02-29T09:00:00Z'],
  ['a leap second', '2026-12-31T23:59:60Z'],
  ['hour 24', '2026-10-05T24:00:00Z'],
  ['month 13', '2026-13-05T09:00:00Z'],
  ['small letters', '2026-10-05t09:00:00z'],
  ['a space in place of T', '2026-10-05 09:00:00Z'],
  ['no seconds', '2026-10-05T09:00Z'],
  ['a line break after it', WHEN + '\n'],
  ['digits of another script', '٢٠٢٦-10-05T09:00:00Z'],
  ['milliseconds', T],
  ['null', null],
  ['empty text', ''],
];

const LABELS = [
  ['a name', 'Example Stationery (invented)'],
  ['one character', 'é'],
  ['200 characters', 'a'.repeat(200)],
  ['201 characters', 'a'.repeat(201)],
  ['200 astral characters', '😀'.repeat(200)],
  ['201 astral characters', '😀'.repeat(201)],
  ['199 letters and an astral character', 'a'.repeat(199) + '😀'],
  ['200 letters and an astral character', 'a'.repeat(200) + '😀'],
  ['a lone first half of a pair', 'a\ud800'],
  ['a lone second half of a pair only', '\udc00'],
  ['a line break', 'a\nb'],
  ['empty text', ''],
  ['a number', 1],
  ['null', null],
  ['a list', ['a']],
];

const ACTIONS = [
  ['a name of the writer', 'supplies.order'],
  ['a shared action', 'provared.order.place'],
  ['an unknown reserved action', 'provared.money.send'],
  ['the reserved prefix alone', 'provared.'],
  ['the prefix without its full stop', 'provared'],
  ['a capital letter', 'Supplies.order'],
  ['64 characters', 'a'.repeat(64)],
  ['65 characters', 'a'.repeat(65)],
  ['empty text', ''],
  ['a leading full stop', '.order'],
  ['a leading hyphen', '-order'],
  ['a leading digit', '9.order'],
  ['an underscore and a hyphen', 'a_b-c'],
  ['a space', 'supplies order'],
  ['a line break after it', 'supplies.order\n'],
  ['a letter with an accent', 'supplies.ordér'],
  ['a digit of another script', 'supplies.٣'],
  ['constructor', 'constructor'],
  ['__proto__', '__proto__'],
  ['toString', 'toString'],
  ['a number', 1],
  ['null', null],
  ['a list', ['supplies.order']],
];

const UNITS = [
  ['GBP', 'GBP'],
  ['small letters', 'gbp'],
  ['16 characters', 'a'.repeat(16)],
  ['17 characters', 'a'.repeat(17)],
  ['a space', 'G P'],
  ['empty text', ''],
  ['a leading full stop', '.GBP'],
  ['a line break after it', 'GBP\n'],
  ['a letter with an accent', 'É'],
  ['a number', 1],
];

const AMOUNTS = [
  ['an amount', { unit: 'GBP', value: 150 }],
  ['a value of 0', { unit: 'GBP', value: 0 }],
  ['the largest value', { unit: 'GBP', value: Number.MAX_SAFE_INTEGER }],
  ['one more than the largest value', { unit: 'GBP', value: Number.MAX_SAFE_INTEGER + 1 }],
  ['a value written with an exponent', { unit: 'GBP', value: 1e21 }],
  ['a negative value', { unit: 'GBP', value: -1 }],
  ['a fraction', { unit: 'GBP', value: 1.5 }],
  ['a value that is text', { unit: 'GBP', value: '1' }],
  ['a value that is true', { unit: 'GBP', value: true }],
  ['a value that is null', { unit: 'GBP', value: null }],
  ['no unit', { value: 1 }],
  ['no value', { unit: 'GBP' }],
  ['an extra member', { unit: 'GBP', value: 1, tax: 0 }],
  ['a list', [{ unit: 'GBP', value: 1 }]],
  ['null', null],
  ['a number', 1],
  ['an empty object', {}],
  ...UNITS.map(([name, unit]) => [`a unit: ${name}`, { unit, value: 1 }]),
];

const DETAILS = [
  ['one document', [DOC]],
  ['32 documents', Array(32).fill(DOC)],
  ['33 documents', Array(33).fill(DOC)],
  ['no documents', []],
  ['an object', { 0: DOC }],
  ['a document without its fingerprint', [{ name: 'order.pdf' }]],
  ['a document without its name', [{ sha256: FP2 }]],
  ['a document with an extra member', [{ ...DOC, size: 1 }]],
  ['a document name of 201 characters', [{ ...DOC, name: 'a'.repeat(201) }]],
  ['an empty document name', [{ ...DOC, name: '' }]],
  ['a document fingerprint of 16 bytes', [{ ...DOC, sha256: ID }]],
  ['a document that is text', ['order.pdf']],
  ['a document that is null', [null]],
  ['a second document that is faulty', [DOC, { ...DOC, sha256: 'x' }]],
];

const SERVICES = [
  ['a service', 'supplier'],
  ['a capital letter', 'Supplier'],
  ['64 characters', 's'.repeat(64)],
  ['65 characters', 's'.repeat(65)],
  ['a reserved name', 'provared.money.send'],
  ['empty text', ''],
  ['a number', 1],
  ['null', null],
];

const KEY_SETS = [
  ['two keys', KEY_SET],
  ['the two keys in the other order', [ML, ED]],
  ['one key', [ED]],
  ['three keys', SEAL_SET],
  ['no keys', []],
  ['an object', { 0: ED, 1: ML }],
  ['null', null],
  ['an ES256 key in place of Ed25519', [ES, ML]],
  ['an SLH-DSA key in place of ML-DSA-87', [ED, SLH]],
  ['an Ed25519 key with an extra member', [{ ...ED, kid: 'a' }, ML]],
  ['an Ed25519 key with a private part', [{ ...ED, d: ED.x }, ML]],
  ['an Ed25519 key of 31 bytes', [{ ...ED, x: b64(31, 4) }, ML]],
  ['an Ed25519 key on another curve', [{ ...ED, crv: 'Ed448' }, ML]],
  ['an Ed25519 key of another type', [{ ...ED, kty: 'EC' }, ML]],
  ['an Ed25519 key that is not base64url', [{ ...ED, x: ED.x + '=' }, ML]],
  ['an Ed25519 key with a member that is not text', [{ ...ED, crv: 1 }, ML]],
  ['an Ed25519 key without its method', [drop(ED, 'alg'), ML]],
  ['an ML-DSA-87 key of 1,952 bytes', [ED, { ...ML, pub: b64(1952, 5) }]],
  ['an ML-DSA-87 key of another type', [ED, { ...ML, kty: 'OKP' }]],
  ['an ML-DSA-65 key', [ED, { ...ML, alg: 'ML-DSA-65' }]],
  ['a key that is a list', [[ED], ML]],
  ['a key that is null', [ED, null]],
];

const SEAL_KEY_SETS = [
  ['three keys', SEAL_SET],
  ['two keys', KEY_SET],
  ['four keys', [...SEAL_SET, SLH]],
  ['the keys in another order', [ED, SLH, ML]],
  ['an SLH-DSA key of 32 bytes', [ED, ML, { ...SLH, pub: b64(32, 6) }]],
  ['an SLH-DSA key of another type', [ED, ML, { ...SLH, kty: 'OKP' }]],
  ['an SLH-DSA key of another strength', [ED, ML, { ...SLH, alg: 'SLH-DSA-SHA2-128s' }]],
  ['a third key that is Ed25519', [ED, ML, ED]],
];

const PASSKEYS = [
  ['an ES256 key', ES],
  ['an RS256 key', RS],
  ['an Ed25519 key', ED],
  ['an ML-DSA-87 key', ML],
  ['an ES256 key on P-384', { ...ES, crv: 'P-384' }],
  ['an ES256 key with a short half', { ...ES, y: b64(31, 8) }],
  ['an ES256 key without one half', drop(ES, 'y')],
  ['an RS256 key with another exponent', { ...RS, e: 'Aw' }],
  ['an RS256 key of 1,024 bits', { ...RS, n: b64(128, 0xc1) }],
  ['an RS256 key of 8,192 bits', { ...RS, n: b64(1024, 0xff) }],
  ['an RS256 key of 8,193 bits', { ...RS, n: toBase64url(new Uint8Array([1, ...new Uint8Array(1024).fill(255)])) }],
  ['an RS256 key with a leading zero', { ...RS, n: toBase64url(new Uint8Array([0, ...new Uint8Array(256).fill(0xc1)])) }],
  ['a key set', KEY_SET],
  ['null', null],
];

const cases = (list) => list.map(([name, content]) => ({ name, content }));

// --- the approval ---

const APPROVAL = { type: 'provared.approval.v0', id: ID, slip: FP, action: 'supplies.order', when: WHEN };
const FULL_APPROVAL = { ...APPROVAL, amount: { unit: 'GBP', value: 150 }, with: 'supplier', details: [DOC] };

function approvalContents() {
  return cases([
    ['the least an approval holds', APPROVAL],
    ['every member', FULL_APPROVAL],
    ['a type of another kind, which this check does not read', { ...APPROVAL, type: 'provared.stub.v0' }],
    ['an unknown member', { ...APPROVAL, colour: 'red' }],
    ['a member of a stub', { ...APPROVAL, seq: 0 }],
    ['a member named __proto__', withProto(APPROVAL)],
    ...NOT_OBJECTS,
    ...missing(APPROVAL, ['action', 'id', 'slip', 'type', 'when']),
    ...each(APPROVAL, 'id', IDS),
    ...each(APPROVAL, 'slip', FINGERPRINTS),
    ...each(APPROVAL, 'action', ACTIONS),
    ...each(APPROVAL, 'amount', AMOUNTS),
    ...each(APPROVAL, 'details', DETAILS),
    ...each(APPROVAL, 'with', SERVICES),
    ...each(APPROVAL, 'when', TIMES),
    ['every field faulty: the id is reported', { ...FULL_APPROVAL, id: 'A', slip: 'A', action: 'A', amount: {}, with: 'S', details: [], when: 'x' }],
    ['a faulty action, amount, service, documents and time: the action is reported', { ...FULL_APPROVAL, action: 'A', amount: {}, with: 'S', details: [], when: 'x' }],
    ['a faulty amount, service, documents and time: the amount is reported', { ...FULL_APPROVAL, amount: {}, with: 'S', details: [], when: 'x' }],
    ['a faulty service, documents and time: the service is reported', { ...FULL_APPROVAL, with: 'S', details: [], when: 'x' }],
    ['faulty documents and time: the documents are reported', { ...FULL_APPROVAL, details: [], when: 'x' }],
  ]);
}

function requests() {
  const stub = {
    type: 'provared.stub.v0',
    id: ID,
    slip: FP,
    seq: 1,
    previous: FP2,
    action: 'supplies.order',
    amount: { unit: 'GBP', value: 150 },
    with: 'supplier',
    details: [DOC],
    approval: FP2,
    terms: FP2,
    pass: FP2,
    when: WHEN,
  };
  const nest = (depth) => (depth === 0 ? 1 : [nest(depth - 1)]);
  return cases([
    ['an approval with only its action', APPROVAL],
    ['an approval with every member', FULL_APPROVAL],
    ['a stub with every member', stub],
    ['the members in another order', { details: [DOC], with: 'supplier', amount: { value: 150, unit: 'GBP' }, action: 'supplies.order' }],
    ['an amount with members of every sort', { action: 'x', amount: { b: [1, 'x', { d: [] }], a: { c: 'd' } } }],
    ['names sorted by UTF-16, not by code point', { action: 'x', amount: { '😀': 1, '￿': 2 } }],
    ['names that are numbers', { action: 'x', amount: { 10: 1, 2: 2, a: 3 } }],
    ['text that must be escaped', { action: 'a"b\\c\n\u0001\u001f\u007f é😀/' }],
    ['a lone surrogate', { action: 'a\ud800' }],
    ['a lone surrogate in a document', { action: 'x', details: [{ name: '\udc00' }] }],
    ['an action that is a number', { action: 7 }],
    ['an action of 0', { action: 0 }],
    ['the largest number', { action: Number.MAX_SAFE_INTEGER }],
    ['one more than the largest number', { action: Number.MAX_SAFE_INTEGER + 1 }],
    ['a negative number', { action: -1 }],
    ['a fraction', { action: 1.5 }],
    ['an action that is true', { action: true }],
    ['an action that is null', { action: null }],
    ['an action that is a list', { action: ['a', 1] }],
    ['no action', { amount: { unit: 'GBP', value: 1 } }],
    ['an empty object', {}],
    ['a service that is null', { action: 'x', with: null }],
    ['documents that are false', { action: 'x', details: false }],
    ['documents nested 7 deep', { action: 'x', details: nest(7) }],
    ['documents nested 8 deep', { action: 'x', details: nest(8) }],
    ['a member named __proto__ beside the action', withProto({ action: 'x' })],
    ['an amount with a member named __proto__', { action: 'x', amount: withProto({ unit: 'GBP' }) }],
    ['a list', [APPROVAL]],
    ['text', 'supplies.order'],
    ['a number', 5],
    ['null', null],
  ]);
}

const APPROVAL_FIELDS = { slip: FP, action: 'supplies.order', id: ID, when: T };

function approvalFields() {
  const list = [
    ['the least an approval holds', APPROVAL_FIELDS],
    ['every member', { ...APPROVAL_FIELDS, amount: { unit: 'GBP', value: 150 }, with: 'supplier', details: [DOC] }],
    ['an unknown field is left out', { ...APPROVAL_FIELDS, colour: 'red' }],
    ['a type given is not used', { ...APPROVAL_FIELDS, type: 'provared.stub.v0' }],
    ['an amount of 0 is left out', { ...APPROVAL_FIELDS, amount: 0 }],
    ['an amount that is false is left out', { ...APPROVAL_FIELDS, amount: false }],
    ['an amount that is empty text is left out', { ...APPROVAL_FIELDS, amount: '' }],
    ['an amount that is null is left out', { ...APPROVAL_FIELDS, amount: null }],
    ['an empty amount', { ...APPROVAL_FIELDS, amount: {} }],
    ['an amount that is an empty list', { ...APPROVAL_FIELDS, amount: [] }],
    ['an amount that is text', { ...APPROVAL_FIELDS, amount: 'GBP 5' }],
    ['an amount that is true', { ...APPROVAL_FIELDS, amount: true }],
    ['a negative amount', { ...APPROVAL_FIELDS, amount: { unit: 'GBP', value: -1 } }],
    ['a service that is empty text is left out', { ...APPROVAL_FIELDS, with: '' }],
    ['a service of 0 is left out', { ...APPROVAL_FIELDS, with: 0 }],
    ['a service that is an empty list', { ...APPROVAL_FIELDS, with: [] }],
    ['a service with a capital letter', { ...APPROVAL_FIELDS, with: 'Supplier' }],
    ['no documents are left out', { ...APPROVAL_FIELDS, details: [] }],
    ['documents that are an empty object are left out', { ...APPROVAL_FIELDS, details: {} }],
    ['documents that are a number are left out', { ...APPROVAL_FIELDS, details: 5 }],
    ['documents that are true are left out', { ...APPROVAL_FIELDS, details: true }],
    ['documents that are an object with a length of 0 are left out', { ...APPROVAL_FIELDS, details: { length: 0 } }],
    ['documents that are an object with a length', { ...APPROVAL_FIELDS, details: { length: 1 } }],
    ['documents that are text', { ...APPROVAL_FIELDS, details: 'order.pdf' }],
    ['33 documents', { ...APPROVAL_FIELDS, details: Array(33).fill(DOC) }],
    ['a document name with a lone surrogate', { ...APPROVAL_FIELDS, details: [{ name: 'a\ud800', sha256: FP2 }] }],
    ['an action with a lone surrogate', { ...APPROVAL_FIELDS, action: 'a\ud800' }],
    ['an empty id', { ...APPROVAL_FIELDS, id: '' }],
    ['an id that is a number', { ...APPROVAL_FIELDS, id: 1 }],
    ['no slip', drop(APPROVAL_FIELDS, 'slip')],
    ['no action', drop(APPROVAL_FIELDS, 'action')],
    ['an unknown reserved action', { ...APPROVAL_FIELDS, action: 'provared.money.send' }],
    ['a shared action', { ...APPROVAL_FIELDS, action: 'provared.order.place' }],
    ['a time of 0', { ...APPROVAL_FIELDS, when: 0 }],
    ['a time before 1970', { ...APPROVAL_FIELDS, when: -1 }],
    ['a time with a fraction of a millisecond', { ...APPROVAL_FIELDS, when: T + 999.9 }],
    ['a negative time with a fraction', { ...APPROVAL_FIELDS, when: -1.5 }],
    ['the year 0', { ...APPROVAL_FIELDS, when: Date.parse('0000-01-01T00:00:00Z') }],
    ['the year before 0', { ...APPROVAL_FIELDS, when: Date.parse('0000-01-01T00:00:00Z') - 1 }],
    ['the last second of the year 9999', { ...APPROVAL_FIELDS, when: Date.parse('9999-12-31T23:59:59Z') + 999 }],
    ['the year 10000', { ...APPROVAL_FIELDS, when: Date.parse('9999-12-31T23:59:59Z') + 1000 }],
    ['the last time a date can hold', { ...APPROVAL_FIELDS, when: 8.64e15 }],
    ['a time beyond what a date can hold', { ...APPROVAL_FIELDS, when: 8.64e15 + 1 }],
  ];
  return list.map(([name, fields]) => ({ name, fields }));
}

/** The values a passkey returns, in hexadecimal, and a preparation to put them with. */
function assemblies(kind, payloadB64) {
  const [protectedB64] = protectedHeaders(kind);
  const base = { prepared: { payloadB64, protectedB64 }, authenticatorData: '01'.repeat(37), clientDataJSON: hex(new TextEncoder().encode('{"type":"webauthn.get"}')), signature: '30440220' + '11'.repeat(32) + '0220' + '22'.repeat(32) };
  // The size of a record is the length of its texts (format description, section 3.1).
  const others = protectedB64.length + toBase64url(bytes(base.authenticatorData)).length + toBase64url(bytes(base.clientDataJSON)).length + toBase64url(bytes(base.signature)).length;
  return [
    { name: 'a record', ...base },
    { name: 'empty values', ...base, authenticatorData: '', clientDataJSON: '', signature: '' },
    { name: 'a record of exactly 65,536 bytes', ...base, prepared: { payloadB64: 'A'.repeat(65536 - others), protectedB64 } },
    { name: 'a record of 65,537 bytes', ...base, prepared: { payloadB64: 'A'.repeat(65537 - others), protectedB64 } },
  ];
}

// --- the refusal and a service's terms ---

const REFUSAL = { type: 'provared.refusal.v0', id: ID, slip: FP, by: BY, action: 'supplies.order', reason: 'over-limit', when: WHEN };

function refusalContents() {
  const reasons = [
    ...Object.keys(REFUSAL_REASONS).map((r) => [r, r]),
    ['an unknown reason', 'because'],
    ['a reason with a capital letter', 'Other'],
    ['a reason that is the text of one', REFUSAL_REASONS.other],
    ['toString', 'toString'],
    ['__proto__', '__proto__'],
    ['hasOwnProperty', 'hasOwnProperty'],
    ['a number', 1],
    ['null', null],
    ['a list', ['other']],
  ];
  return cases([
    ['a refusal', REFUSAL],
    ['with an amount', { ...REFUSAL, amount: { unit: 'GBP', value: 250 } }],
    ['a type of another kind, which this check does not read', { ...REFUSAL, type: 'provared.terms.v0' }],
    ['an unknown member', { ...REFUSAL, colour: 'red' }],
    ['documents, which a refusal does not hold', { ...REFUSAL, details: [DOC] }],
    ['a service, which a refusal does not hold', { ...REFUSAL, with: 'supplier' }],
    ['a member named __proto__', withProto(REFUSAL)],
    ...NOT_OBJECTS,
    ...missing(REFUSAL, ['action', 'by', 'id', 'reason', 'slip', 'type', 'when']),
    ...missing(REFUSAL, ['keys', 'name'], 'by'),
    ...each(REFUSAL, 'id', IDS),
    ...each(REFUSAL, 'slip', FINGERPRINTS),
    ['by: a list', { ...REFUSAL, by: [BY] }],
    ['by: null', { ...REFUSAL, by: null }],
    ['by: an extra member', { ...REFUSAL, by: { ...BY, url: 'https://example.org' } }],
    ...each(REFUSAL, 'by.name', LABELS),
    ...each(REFUSAL, 'by.keys', KEY_SETS),
    ...each(REFUSAL, 'action', ACTIONS),
    ...each(REFUSAL, 'amount', AMOUNTS),
    ...each(REFUSAL, 'reason', reasons),
    ...each(REFUSAL, 'when', TIMES),
    ['a faulty name and keys: the name is reported', { ...REFUSAL, by: { name: '', keys: [] } }],
    ['a faulty action, amount, reason and time: the action is reported', { ...REFUSAL, action: 'A', amount: {}, reason: 'x', when: 'x' }],
    ['a faulty amount, reason and time: the amount is reported', { ...REFUSAL, amount: {}, reason: 'x', when: 'x' }],
    ['a faulty reason and time: the reason is reported', { ...REFUSAL, reason: 'x', when: 'x' }],
  ]);
}

const TERMS = { type: 'provared.terms.v0', id: ID, by: BY, accepts: ['supplies.order', 'provared.order.place'], never: ['destroys', 'deceive'], validFrom: FROM, validUntil: UNTIL };
const ALL_NEVER = ['reads', 'changes', 'destroys', 'sends', 'commits', 'grants', 'runs', 'enters', 'impersonate', 'bypass', 'escalate', 'conceal', 'deceive', 'harass', 'disclose', 'continue-after-stop'];

function termsContents() {
  const names = Array.from({ length: 65 }, (_, i) => `action.${i}`);
  return cases([
    ['terms', TERMS],
    ['nothing forbidden', { ...TERMS, never: [] }],
    ['a time, which terms do not hold', { ...TERMS, when: WHEN }],
    ['a type of another kind, which this check does not read', { ...TERMS, type: 'provared.refusal.v0' }],
    ['an unknown member', { ...TERMS, colour: 'red' }],
    ['a member named __proto__', withProto(TERMS)],
    ...NOT_OBJECTS,
    ...missing(TERMS, ['accepts', 'by', 'id', 'never', 'type', 'validFrom', 'validUntil']),
    ...missing(TERMS, ['keys', 'name'], 'by'),
    ...each(TERMS, 'id', IDS),
    ['by: a list', { ...TERMS, by: [BY] }],
    ...each(TERMS, 'by.name', LABELS),
    ...each(TERMS, 'by.keys', KEY_SETS),
    ...ACTIONS.map(([name, a]) => [`accepts: ${name}`, { ...TERMS, accepts: ['supplies.order', a], never: [] }]),
    ['accepts: one action', { ...TERMS, accepts: ['supplies.order'] }],
    ['accepts: 64 actions', { ...TERMS, accepts: names.slice(0, 64) }],
    ['accepts: 65 actions', { ...TERMS, accepts: names }],
    ['accepts: none', { ...TERMS, accepts: [] }],
    ['accepts: a repeated action', { ...TERMS, accepts: ['supplies.order', 'supplies.order'] }],
    ['accepts: text', { ...TERMS, accepts: 'supplies.order' }],
    ['accepts: an object', { ...TERMS, accepts: { 0: 'supplies.order' } }],
    ['accepts: null', { ...TERMS, accepts: null }],
    ['never: every kind of action and every rule of conduct', { ...TERMS, accepts: ['supplies.order'], never: ALL_NEVER }],
    ['never: 17 names', { ...TERMS, accepts: ['supplies.order'], never: [...ALL_NEVER, 'deceive'] }],
    ['never: a repeated name', { ...TERMS, never: ['deceive', 'deceive'] }],
    ['never: an unknown name', { ...TERMS, never: ['steal'] }],
    ['never: a name with a capital letter', { ...TERMS, never: ['Deceive'] }],
    ['never: a shared action, not a kind', { ...TERMS, never: ['provared.data.delete'] }],
    ['never: toString', { ...TERMS, never: ['toString'] }],
    ['never: constructor', { ...TERMS, never: ['constructor'] }],
    ['never: __proto__', { ...TERMS, never: ['__proto__'] }],
    ['never: a number', { ...TERMS, never: [1] }],
    ['never: null', { ...TERMS, never: [null] }],
    ['never: text', { ...TERMS, never: 'deceive' }],
    ['never: a kind the terms accept', { ...TERMS, never: ['commits'] }],
    ['never: a kind of another shared action', { ...TERMS, accepts: ['provared.data.read'], never: ['changes'] }],
    ['never: a kind, beside an action of the writer', { ...TERMS, accepts: ['supplies.delete'], never: ['destroys'] }],
    ['never: the kind of the second action accepted', { ...TERMS, accepts: ['supplies.order', 'provared.data.delete'], never: ['destroys'] }],
    ...each(TERMS, 'validFrom', TIMES),
    ...each(TERMS, 'validUntil', TIMES),
    ['an end at the start', { ...TERMS, validUntil: FROM }],
    ['an end one second after the start', { ...TERMS, validUntil: '2026-10-05T08:00:01Z' }],
    ['an end before the start', { ...TERMS, validFrom: UNTIL, validUntil: FROM }],
    ['a repeated action and an unknown prohibition: the action is reported', { ...TERMS, accepts: ['a', 'a'], never: ['steal'] }],
    ['an unknown prohibition and a faulty time: the prohibition is reported', { ...TERMS, never: ['steal'], validFrom: 'x' }],
    ['a faulty start and a faulty end: the start is reported', { ...TERMS, validFrom: 'x', validUntil: 'y' }],
  ]);
}

// --- the cancellation, the acknowledgement, the vouching record and the withdrawal ---

const CANCELLATION = { type: 'provared.cancellation.v0', id: ID, slip: FP, when: WHEN };

function cancellationContents() {
  return cases([
    ['a cancellation', CANCELLATION],
    ['a type of another kind, which this check does not read', { ...CANCELLATION, type: 'provared.slip.v0' }],
    ['an unknown member', { ...CANCELLATION, reason: 'changed my mind' }],
    ['a pass, which a cancellation does not hold', { ...CANCELLATION, pass: FP2 }],
    ['a member named __proto__', withProto(CANCELLATION)],
    ...NOT_OBJECTS,
    ...missing(CANCELLATION, ['id', 'slip', 'type', 'when']),
    ...each(CANCELLATION, 'id', IDS),
    ...each(CANCELLATION, 'slip', FINGERPRINTS),
    ...each(CANCELLATION, 'when', TIMES),
    ['a faulty id, slip and time: the id is reported', { ...CANCELLATION, id: 'x', slip: 'x', when: 'x' }],
    ['a faulty slip and time: the slip is reported', { ...CANCELLATION, slip: 'x', when: 'x' }],
  ]);
}

const ACKNOWLEDGEMENT = { type: 'provared.acknowledgement.v0', id: ID, slip: FP, cancellation: FP2, when: WHEN };

function acknowledgementContents() {
  return cases([
    ['an acknowledgement', ACKNOWLEDGEMENT],
    ['an acknowledgement of a helper agent', { ...ACKNOWLEDGEMENT, pass: b64(32, 9) }],
    ['a type of another kind, which this check does not read', { ...ACKNOWLEDGEMENT, type: 'provared.cancellation.v0' }],
    ['an unknown member', { ...ACKNOWLEDGEMENT, colour: 'red' }],
    ['a member named __proto__', withProto(ACKNOWLEDGEMENT)],
    ...NOT_OBJECTS,
    ...missing(ACKNOWLEDGEMENT, ['cancellation', 'id', 'slip', 'type', 'when']),
    ...each(ACKNOWLEDGEMENT, 'id', IDS),
    ...each(ACKNOWLEDGEMENT, 'slip', FINGERPRINTS),
    ...each(ACKNOWLEDGEMENT, 'cancellation', FINGERPRINTS),
    ...each(ACKNOWLEDGEMENT, 'pass', FINGERPRINTS),
    ...each(ACKNOWLEDGEMENT, 'when', TIMES),
    ['a faulty slip, cancellation, pass and time: the slip is reported', { ...ACKNOWLEDGEMENT, slip: 'x', cancellation: 'x', pass: 'x', when: 'x' }],
    ['a faulty cancellation, pass and time: the cancellation is reported', { ...ACKNOWLEDGEMENT, cancellation: 'x', pass: 'x', when: 'x' }],
    ['a faulty pass and time: the pass is reported', { ...ACKNOWLEDGEMENT, pass: 'x', when: 'x' }],
  ]);
}

const PERSON = { kind: 'person', name: 'Sam Example', key: ES };
const VOUCHING = { type: 'provared.vouching.v0', id: ID, by: { name: 'Example Ltd (invented)', keys: KEY_SET }, for: PERSON, validFrom: FROM, validUntil: UNTIL, when: WHEN };

function vouchingContents() {
  const agent = { kind: 'agent', name: 'Office supplies agent', keys: KEY_SET };
  const service = { kind: 'service', name: 'Example Stationery (invented)', keys: KEY_SET };
  const recorder = { kind: 'recorder', name: 'Example recorder (invented)', keys: SEAL_SET };
  const kinds = [
    ['an organisation', 'organisation'],
    ['a capital letter', 'Person'],
    ['toString', 'toString'],
    ['__proto__', '__proto__'],
    ['hasOwnProperty', 'hasOwnProperty'],
    ['empty text', ''],
    ['a number', 1],
    ['null', null],
    ['a list', ['person']],
  ];
  return cases([
    ['a person', VOUCHING],
    ['an agent', { ...VOUCHING, for: agent }],
    ['a service', { ...VOUCHING, for: service }],
    ['a recorder', { ...VOUCHING, for: recorder }],
    ['a type of another kind, which this check does not read', { ...VOUCHING, type: 'provared.withdrawal.v0' }],
    ['an unknown member', { ...VOUCHING, colour: 'red' }],
    ['a member named __proto__', withProto(VOUCHING)],
    ...NOT_OBJECTS,
    ...missing(VOUCHING, ['by', 'for', 'id', 'type', 'validFrom', 'validUntil', 'when']),
    ...missing(VOUCHING, ['keys', 'name'], 'by'),
    ...each(VOUCHING, 'id', IDS),
    ['by: a list', { ...VOUCHING, by: [VOUCHING.by] }],
    ['by: null', { ...VOUCHING, by: null }],
    ['by: an extra member', { ...VOUCHING, by: { ...VOUCHING.by, url: 'https://example.org' } }],
    ...each(VOUCHING, 'by.name', LABELS),
    ...each(VOUCHING, 'by.keys', KEY_SETS),
    // Whom it vouches for.
    ['for: a list', { ...VOUCHING, for: [PERSON] }],
    ['for: null', { ...VOUCHING, for: null }],
    ['for: text', { ...VOUCHING, for: 'person' }],
    ['for: an empty object', { ...VOUCHING, for: {} }],
    ...kinds.map(([name, kind]) => [`for.kind: ${name}`, { ...VOUCHING, for: { ...PERSON, kind } }]),
    ...missing(VOUCHING, ['key', 'kind', 'name'], 'for'),
    ['for: a person with keys in place of a key', { ...VOUCHING, for: { kind: 'person', name: 'Sam Example', keys: KEY_SET } }],
    ['for: a person with a key and keys', { ...VOUCHING, for: { ...PERSON, keys: KEY_SET } }],
    ['for: a person with an extra member', { ...VOUCHING, for: { ...PERSON, email: 'sam@example.org' } }],
    ...PASSKEYS.map(([name, key]) => [`for.key of a person: ${name}`, { ...VOUCHING, for: { ...PERSON, key } }]),
    ['for: an agent with a key in place of keys', { ...VOUCHING, for: { kind: 'agent', name: agent.name, key: ED } }],
    ['for: an agent with an extra member', { ...VOUCHING, for: { ...agent, url: 'https://example.org' } }],
    ['for: an agent without keys', { ...VOUCHING, for: drop(agent, 'keys') }],
    ['for: an agent without a name', { ...VOUCHING, for: drop(agent, 'name') }],
    ...KEY_SETS.map(([name, keys]) => [`for.keys of an agent: ${name}`, { ...VOUCHING, for: { ...agent, keys } }]),
    ...KEY_SETS.map(([name, keys]) => [`for.keys of a service: ${name}`, { ...VOUCHING, for: { ...service, keys } }]),
    ...SEAL_KEY_SETS.map(([name, keys]) => [`for.keys of a recorder: ${name}`, { ...VOUCHING, for: { ...recorder, keys } }]),
    ...LABELS.map(([name, label]) => [`for.name: ${name}`, { ...VOUCHING, for: { ...PERSON, name: label } }]),
    ['for: a faulty key and name: the key is reported', { ...VOUCHING, for: { ...PERSON, name: '', key: ML } }],
    ['for: a faulty kind and members: the kind is reported', { ...VOUCHING, for: { kind: 'organisation', colour: 'red' } }],
    ['for: a recorder with a faulty name and keys: the keys are reported', { ...VOUCHING, for: { ...recorder, name: '', keys: KEY_SET } }],
    ...each(VOUCHING, 'validFrom', TIMES),
    ...each(VOUCHING, 'validUntil', TIMES),
    ...each(VOUCHING, 'when', TIMES),
    ['an end at the start', { ...VOUCHING, validUntil: FROM }],
    ['an end before the start', { ...VOUCHING, validFrom: UNTIL, validUntil: FROM }],
    ['a time after the end, which this check allows', { ...VOUCHING, when: '2027-01-01T00:00:00Z' }],
    ['a time before the start, which this check allows', { ...VOUCHING, when: '2020-01-01T00:00:00Z' }],
    ['faulty keys of its own and a faulty kind: the keys are reported', { ...VOUCHING, by: { ...VOUCHING.by, keys: [] }, for: { kind: 'x' } }],
    ['a faulty name and a faulty time: the name is reported', { ...VOUCHING, for: { ...PERSON, name: '' }, validFrom: 'x' }],
    ['an end before the start and a faulty time: the end is reported', { ...VOUCHING, validUntil: FROM, when: 'x' }],
  ]);
}

const WITHDRAWAL = { type: 'provared.withdrawal.v0', id: ID, vouching: FP, when: WHEN };

function withdrawalContents() {
  return cases([
    ['a withdrawal', WITHDRAWAL],
    ['a type of another kind, which this check does not read', { ...WITHDRAWAL, type: 'provared.vouching.v0' }],
    ['an unknown member', { ...WITHDRAWAL, reason: 'left the company' }],
    ['a slip, which a withdrawal does not hold', { ...WITHDRAWAL, slip: FP2 }],
    ['a member named __proto__', withProto(WITHDRAWAL)],
    ...NOT_OBJECTS,
    ...missing(WITHDRAWAL, ['id', 'type', 'vouching', 'when']),
    ...each(WITHDRAWAL, 'id', IDS),
    ...each(WITHDRAWAL, 'vouching', FINGERPRINTS),
    ...each(WITHDRAWAL, 'when', TIMES),
    ['a faulty id, vouching record and time: the id is reported', { ...WITHDRAWAL, id: 'x', vouching: 'x', when: 'x' }],
    ['a faulty vouching record and time: the vouching record is reported', { ...WITHDRAWAL, vouching: 'x', when: 'x' }],
  ]);
}

// --- the pass ---

const PASS = {
  type: 'provared.pass.v0',
  id: ID,
  slip: FP,
  to: { name: 'Helper agent', keys: KEY_SET },
  actions: ['supplies.order', 'provared.message.send'],
  limits: [{ action: 'supplies.order', max: 100, unit: 'GBP' }],
  validFrom: FROM,
  validUntil: UNTIL,
  when: WHEN,
};

function passContents() {
  const names = Array.from({ length: 65 }, (_, i) => `action.${i}`);
  const order = 'supplies.order';
  const send = 'provared.message.send';
  const limits = [
    ['none', []],
    ['a total', [{ action: order, max: 100, unit: 'GBP' }]],
    ['a total of 0', [{ action: order, max: 0, unit: 'GBP' }]],
    ['the largest total', [{ action: order, max: Number.MAX_SAFE_INTEGER, unit: 'GBP' }]],
    ['one more than the largest total', [{ action: order, max: Number.MAX_SAFE_INTEGER + 1, unit: 'GBP' }]],
    ['a negative total', [{ action: order, max: -1, unit: 'GBP' }]],
    ['a total that is a fraction', [{ action: order, max: 1.5, unit: 'GBP' }]],
    ['a total that is text', [{ action: order, max: '1', unit: 'GBP' }]],
    ['a total that is true', [{ action: order, max: true, unit: 'GBP' }]],
    ['a total that is null', [{ action: order, max: null, unit: 'GBP' }]],
    ['a limit on each action', [{ action: order, each: 50, unit: 'GBP' }]],
    ['a count', [{ action: send, count: 3 }]],
    ['a count of 1', [{ action: send, count: 1 }]],
    ['a count of 0', [{ action: send, count: 0 }]],
    ['a count with a unit', [{ action: send, count: 1, unit: 'GBP' }]],
    ['a count that is true', [{ action: send, count: true }]],
    ['a total without a unit', [{ action: order, max: 1 }]],
    ['a limit on each action without a unit', [{ action: order, each: 1 }]],
    ['a limit with no kind', [{ action: order, unit: 'GBP' }]],
    ['a limit with two kinds', [{ action: order, max: 1, each: 1, unit: 'GBP' }]],
    ['a limit with three kinds', [{ action: order, max: 1, each: 1, count: 1, unit: 'GBP' }]],
    ['a total and a count', [{ action: order, max: 1, count: 1 }]],
    ['a total in a period', [{ action: order, max: 100, unit: 'GBP', per: 86400 }]],
    ['a count in a period', [{ action: send, count: 3, per: 3600 }]],
    ['a period of 1 second', [{ action: send, count: 3, per: 1 }]],
    ['a period of 366 days', [{ action: send, count: 3, per: 366 * 86400 }]],
    ['a period of 366 days and a second', [{ action: send, count: 3, per: 366 * 86400 + 1 }]],
    ['a period of 0', [{ action: send, count: 3, per: 0 }]],
    ['a negative period', [{ action: send, count: 3, per: -60 }]],
    ['a period that is a fraction', [{ action: send, count: 3, per: 1.5 }]],
    ['a period that is text', [{ action: send, count: 3, per: '60' }]],
    ['a period on each action', [{ action: order, each: 1, unit: 'GBP', per: 60 }]],
    ['a limit on an action the pass does not hold', [{ action: 'other', max: 1, unit: 'GBP' }]],
    ['a limit on an action of another case', [{ action: 'Supplies.order', max: 1, unit: 'GBP' }]],
    ['a limit on an action that is a list', [{ action: [order], max: 1, unit: 'GBP' }]],
    ['a limit on an action that is a number', [{ action: 1, max: 1, unit: 'GBP' }]],
    ['a limit without an action', [{ max: 1, unit: 'GBP' }]],
    ['a limit with an extra member', [{ action: order, max: 1, unit: 'GBP', note: 'x' }]],
    ['a limit that is text', ['supplies.order']],
    ['a limit that is null', [null]],
    ['a limit that is a list', [[order, 1]]],
    ['the same limit twice', [{ action: order, max: 1, unit: 'GBP' }, { action: order, max: 2, unit: 'GBP' }]],
    ['the same count twice', [{ action: send, count: 1 }, { action: send, count: 2 }]],
    ['the same count in the same period twice', [{ action: send, count: 1, per: 60 }, { action: send, count: 2, per: 60 }]],
    ['a count in two periods', [{ action: send, count: 1, per: 60 }, { action: send, count: 2, per: 3600 }]],
    ['a count and a count in a period', [{ action: send, count: 5 }, { action: send, count: 2, per: 60 }]],
    ['a total, a total in a period and a limit on each action', [{ action: order, max: 100, unit: 'GBP' }, { action: order, max: 50, unit: 'GBP', per: 86400 }, { action: order, each: 20, unit: 'GBP' }]],
    ['two units for one action', [{ action: order, max: 1, unit: 'GBP' }, { action: order, each: 2, unit: 'EUR' }]],
    ['two units for two actions', [{ action: order, max: 1, unit: 'GBP' }, { action: send, max: 2, unit: 'messages' }]],
    ['the same limit on two actions', [{ action: order, count: 1 }, { action: send, count: 1 }]],
    ...UNITS.map(([name, unit]) => [`a unit: ${name}`, [{ action: order, max: 1, unit }]]),
    ['64 limits', Array.from({ length: 64 }, (_, i) => ({ action: order, count: 1, per: i + 1 }))],
    ['65 limits', Array.from({ length: 65 }, (_, i) => ({ action: order, count: 1, per: i + 1 }))],
    ['an object', { 0: { action: order, max: 1, unit: 'GBP' } }],
    ['null', null],
    ['a faulty unit and a repeated limit: the unit is reported', [{ action: order, max: 1, unit: 'GBP' }, { action: order, max: 2, unit: 'G P' }]],
  ];
  return cases([
    ['a pass', PASS],
    ['a pass from a helper', { ...PASS, from: FP2 }],
    ['a type of another kind, which this check does not read', { ...PASS, type: 'provared.slip.v0' }],
    ['an unknown member', { ...PASS, colour: 'red' }],
    ['a number of passes, which a pass does not hold', { ...PASS, passes: 1 }],
    ['conditions, which a pass does not hold', { ...PASS, requires: [] }],
    ['a member named __proto__', withProto(PASS)],
    ...NOT_OBJECTS,
    ...missing(PASS, ['actions', 'id', 'limits', 'slip', 'to', 'type', 'validFrom', 'validUntil', 'when']),
    ...missing(PASS, ['keys', 'name'], 'to'),
    ...each(PASS, 'id', IDS),
    ...each(PASS, 'slip', FINGERPRINTS),
    ...each(PASS, 'from', FINGERPRINTS),
    ['to: a list', { ...PASS, to: [PASS.to] }],
    ['to: null', { ...PASS, to: null }],
    ['to: an extra member', { ...PASS, to: { ...PASS.to, software: [] } }],
    ...each(PASS, 'to.name', LABELS),
    ...each(PASS, 'to.keys', KEY_SETS),
    ['to: a recorder key set', { ...PASS, to: { ...PASS.to, keys: SEAL_SET } }],
    ...ACTIONS.map(([name, a]) => [`actions: ${name}`, { ...PASS, actions: [order, a] }]),
    ['actions: one action', { ...PASS, actions: [order] }],
    ['actions: 64 actions', { ...PASS, actions: names.slice(0, 64), limits: [] }],
    ['actions: 65 actions', { ...PASS, actions: names, limits: [] }],
    ['actions: none', { ...PASS, actions: [], limits: [] }],
    ['actions: a repeated action', { ...PASS, actions: [order, order] }],
    ['actions: text', { ...PASS, actions: order }],
    ['actions: null', { ...PASS, actions: null }],
    ...limits.map(([name, l]) => [`limits: ${name}`, { ...PASS, limits: l }]),
    ...each(PASS, 'validFrom', TIMES),
    ...each(PASS, 'validUntil', TIMES),
    ...each(PASS, 'when', TIMES),
    ['an end at the start', { ...PASS, validUntil: FROM }],
    ['an end before the start', { ...PASS, validFrom: UNTIL, validUntil: FROM }],
    ['a faulty helper name and keys: the name is reported', { ...PASS, to: { name: '', keys: [] } }],
    ['a repeated action and a faulty limit: the action is reported', { ...PASS, actions: [order, order], limits: [null] }],
    ['a faulty limit and a faulty time: the limit is reported', { ...PASS, limits: [null], validFrom: 'x' }],
    ['a faulty from and faulty helper: the from is reported', { ...PASS, from: 'x', to: null }],
  ]);
}

// --- writing records ---

const writes = (list) => list.map(([name, fields]) => ({ name, seed: SEED, fields }));

function refusalFields() {
  const base = { id: ID, slip: FP, by: BY, action: 'supplies.order', reason: 'over-limit', when: T };
  return writes([
    ['a refusal', base],
    ['with an amount', { ...base, amount: { unit: 'GBP', value: 250 } }],
    ['an amount of 0 is left out', { ...base, amount: 0 }],
    ['an empty amount', { ...base, amount: {} }],
    ['an unknown field is left out', { ...base, colour: 'red' }],
    ['an unknown reserved action', { ...base, action: 'provared.money.send' }],
    ['an unknown reason', { ...base, reason: 'because' }],
    ['no service', drop(base, 'by')],
    ['a service name with a lone surrogate', { ...base, by: { ...BY, name: 'a\ud800' } }],
    ['a time of 0', { ...base, when: 0 }],
    ['the year 10000', { ...base, when: Date.parse('9999-12-31T23:59:59Z') + 1000 }],
    ...Object.keys(REFUSAL_REASONS).map((reason) => [`the reason ${reason}`, { ...base, reason }]),
  ]);
}

function termsFields() {
  const base = { id: ID, by: BY, accepts: ['supplies.order', 'provared.order.place'], never: ['destroys'], validFrom: FROM, validUntil: UNTIL };
  return writes([
    ['terms', base],
    ['nothing forbidden, by default', drop(base, 'never')],
    ['nothing forbidden, given as null', { ...base, never: null }],
    ['a time is not written', { ...base, when: T }],
    ['a kind the terms accept is forbidden', { ...base, never: ['commits'] }],
    ['no start', drop(base, 'validFrom')],
    ['a start given in milliseconds', { ...base, validFrom: T }],
  ]);
}

function acknowledgementFields() {
  const base = { id: ID, slip: FP, cancellation: FP2, when: T };
  return writes([
    ['an acknowledgement', base],
    ['of a helper agent', { ...base, pass: b64(32, 9) }],
    ['a pass that is empty text is left out', { ...base, pass: '' }],
    ['a pass of 0 is left out', { ...base, pass: 0 }],
    ['a pass that is an empty object', { ...base, pass: {} }],
    ['a pass that is too short', { ...base, pass: ID }],
    ['no cancellation', drop(base, 'cancellation')],
    ['a time before 1970', { ...base, when: -1000 }],
  ]);
}

function vouchingFields() {
  const base = { id: ID, by: VOUCHING.by, for: PERSON, validFrom: FROM, validUntil: UNTIL, when: T };
  return writes([
    ['for a person', base],
    ['for an agent', { ...base, for: { kind: 'agent', name: 'Office supplies agent', keys: KEY_SET } }],
    ['for a service', { ...base, for: { kind: 'service', name: 'Example Stationery (invented)', keys: KEY_SET } }],
    ['for a recorder', { ...base, for: { kind: 'recorder', name: 'Example recorder (invented)', keys: SEAL_SET } }],
    ['for an unknown kind', { ...base, for: { ...PERSON, kind: 'organisation' } }],
    ['an end before the start', { ...base, validFrom: UNTIL, validUntil: FROM }],
    ['a name with an astral character', { ...base, for: { ...PERSON, name: 'Sam 😀' } }],
  ]);
}

function withdrawalFields() {
  const base = { id: ID, vouching: FP, when: T };
  return writes([
    ['a withdrawal', base],
    ['a faulty vouching record', { ...base, vouching: 'x' }],
    ['an unknown field is left out', { ...base, slip: FP2 }],
  ]);
}

function passFields() {
  const base = {
    id: ID,
    slip: FP,
    to: { name: 'Helper agent', keys: KEY_SET },
    actions: ['supplies.order', 'provared.message.send'],
    limits: [{ action: 'supplies.order', max: 100, unit: 'GBP', per: 86400 }],
    validFrom: FROM,
    validUntil: UNTIL,
    when: T,
  };
  return writes([
    ['a pass', base],
    ['a pass from a helper', { ...base, from: FP2 }],
    ['no limits, by default', drop(base, 'limits')],
    ['no limits, given as null', { ...base, limits: null }],
    ['a from that is empty text is left out', { ...base, from: '' }],
    ['a from that is an empty list', { ...base, from: [] }],
    ['a limit on an action the pass does not hold', { ...base, limits: [{ action: 'other', count: 1 }] }],
    ['no actions', { ...base, actions: [], limits: [] }],
  ]);
}

// --- each set ---

/** Each set of cases, by the name of its file. */
export const CASES = {
  'approval-contents': () => finish("Confirming the members of an approval's content (format description, section 17).", 'validateApprovalContent', approvalContents(), ANSWER),
  'approval-requests': () => finish('What an approval and a stub must agree on, as text in the canonical form (format description, section 17).', 'requestOf', requests(), ANSWER),
  'approvals-prepared': () => finish("Building an approval's content and the challenge a passkey must sign (format description, section 17).", 'prepareApproval', approvalFields(), ANSWER),
  'approvals-assembled': async () =>
    finish("Putting a passkey's three values with a prepared approval (format description, section 17).", 'assembleApproval', assemblies('approval', (await prepareApproval(APPROVAL_FIELDS)).payloadB64), ANSWER),
  'refusal-contents': () => finish("Confirming the members of a refusal's content (format description, section 18).", 'validateRefusalContent', refusalContents(), ANSWER),
  'terms-contents': () => finish("Confirming the members of a service's terms for agents (format description, section 19).", 'validateTermsContent', termsContents(), ANSWER),
  'refusals-written': () => finish('Writing and signing a refusal (format description, section 18).', 'writeRefusal', refusalFields(), ANSWER),
  'terms-written': () => finish("Writing and signing a service's terms for agents (format description, section 19).", 'writeTerms', termsFields(), ANSWER),
  'cancellation-contents': () => finish("Confirming the members of a cancellation's content (format description, section 22).", 'validateCancellationContent', cancellationContents(), ANSWER),
  'acknowledgement-contents': () => finish("Confirming the members of an acknowledgement's content (format description, section 26).", 'validateAcknowledgementContent', acknowledgementContents(), ANSWER),
  'vouching-contents': () => finish("Confirming the members of a vouching record's content (format description, section 23).", 'validateVouchingContent', vouchingContents(), ANSWER),
  'withdrawal-contents': () => finish("Confirming the members of a withdrawal's content (format description, section 23).", 'validateWithdrawalContent', withdrawalContents(), ANSWER),
  'cancellations-prepared': () =>
    finish(
      "Building a cancellation's content and the challenge a passkey must sign (format description, section 22).",
      'prepareCancellation',
      [
        ['a cancellation', { id: ID, slip: FP, when: T }],
        ['an unknown field is left out', { id: ID, slip: FP, when: T, pass: FP2 }],
        ['no slip', { id: ID, when: T }],
        ['a slip of 16 bytes', { id: ID, slip: ID, when: T }],
        ['an id of 32 bytes', { id: FP, slip: FP, when: T }],
        ['a time of 0', { id: ID, slip: FP, when: 0 }],
        ['the year 10000', { id: ID, slip: FP, when: Date.parse('9999-12-31T23:59:59Z') + 1000 }],
        ['a time beyond what a date can hold', { id: ID, slip: FP, when: -8.64e15 - 1 }],
      ].map(([name, fields]) => ({ name, fields })),
      ANSWER,
    ),
  'cancellations-assembled': async () =>
    finish(
      "Putting a passkey's three values with a prepared cancellation (format description, section 22).",
      'assembleCancellation',
      assemblies('cancellation', (await prepareCancellation({ id: ID, slip: FP, when: T })).payloadB64).slice(0, 2),
      ANSWER,
    ),
  'acknowledgements-written': () => finish('Writing and signing an acknowledgement (format description, section 26).', 'writeAcknowledgement', acknowledgementFields(), ANSWER),
  'vouchings-written': () => finish('Writing and signing a vouching record (format description, section 23).', 'writeVouching', vouchingFields(), ANSWER),
  'withdrawals-written': () => finish('Writing and signing a withdrawal (format description, section 23).', 'writeWithdrawal', withdrawalFields(), ANSWER),
  'pass-contents': () => finish("Confirming the members of a pass's content, with its own limits (format description, section 25).", 'validatePassContent', passContents(), ANSWER),
  'passes-written': () => finish('Writing and signing a pass (format description, section 25).', 'writePass', passFields(), ANSWER),
  'record-constants': () =>
    finish('The reasons a service may give for a refusal, the kinds a vouching record may vouch for, and the most passes in a row.', 'recordConstants', [{ name: 'the constants' }], ANSWER),
};
