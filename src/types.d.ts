// Type declarations for Provared, draft version 0.
//
// These describe the shapes the library takes and returns, so that an editor
// can check how it is called. They change nothing about how the library
// runs. The format itself is described in spec/provared-format.md.

/** Text in base64url with no padding. */
export type Base64url = string;
/** A SHA-256 fingerprint in base64url: 43 characters. */
export type Fingerprint = string;
/** A time written as YYYY-MM-DDTHH:MM:SSZ. */
export type Time = string;

// --- keys ---

export interface Ed25519Key {
  alg: 'Ed25519';
  crv: 'Ed25519';
  kty: 'OKP';
  x: Base64url;
}
export interface MlDsaKey {
  alg: 'ML-DSA-87';
  kty: 'AKP';
  pub: Base64url;
}
export interface SlhDsaKey {
  alg: 'SLH-DSA-SHA2-256s';
  kty: 'AKP';
  pub: Base64url;
}
export interface Es256Key {
  alg: 'ES256';
  crv: 'P-256';
  kty: 'EC';
  x: Base64url;
  y: Base64url;
}
export interface Rs256Key {
  alg: 'RS256';
  e: 'AQAB';
  kty: 'RSA';
  n: Base64url;
}
/** The public key of a person's passkey. */
export type PasskeyKey = Es256Key | Rs256Key | Ed25519Key;
/** The two keys of an agent, a service or an organisation. */
export type KeySet = [Ed25519Key, MlDsaKey];
/** The three keys of a recorder, which signs seals. */
export type SealKeySet = [Ed25519Key, MlDsaKey, SlhDsaKey];
export type PublicKey = PasskeyKey | MlDsaKey | SlhDsaKey;

// --- what records hold ---

export interface Amount {
  unit: string;
  value: number;
}
export interface DocumentRef {
  name: string;
  sha256: Fingerprint;
}
export type Limit =
  | { action: string; max: number; unit: string; per?: number }
  | { action: string; each: number; unit: string }
  | { action: string; count: number; per?: number };
export interface Condition {
  need: 'approval' | 'countersignature';
  action?: string;
  above?: number;
  unit?: string;
}
export interface Service {
  id: string;
  name: string;
  keys?: KeySet;
}
export interface Party {
  keys: KeySet;
  name: string;
}
export interface SlipFields {
  id?: Base64url;
  issuer: { name: string; key: PasskeyKey; rpId: string; origin: string };
  agent: { name: string; keys: KeySet; software?: DocumentRef[] };
  actions: string[];
  limits: Limit[];
  /** Defaults to an empty list. */
  requires?: Condition[];
  /** Kinds of action and rules of conduct. Defaults to an empty list. */
  never?: string[];
  with: Service[];
  /** How many times the permission may be passed on to a helper agent: 1 to 10. Absent: not at all. */
  passes?: number;
  validFrom: Time;
  validUntil: Time;
  purpose: string;
}
/**
 * A slip's content as the checker hands it back. A name or the purpose
 * that is covered, and was not revealed, is absent.
 */
export interface SlipContent extends Required<Omit<SlipFields, 'id' | 'passes' | 'issuer' | 'agent' | 'with' | 'purpose'>> {
  issuer: { name?: string; key: PasskeyKey; rpId: string; origin: string };
  agent: { name?: string; keys: KeySet; software?: DocumentRef[] };
  with: { id: string; name?: string; keys?: KeySet }[];
  purpose?: string;
  passes?: number;
  type: 'provared.slip.v0';
  id: Base64url;
}
export interface Request {
  action: string;
  amount?: Amount;
  with?: string;
  details?: DocumentRef[];
}
export interface StubContent extends Request {
  type: 'provared.stub.v0';
  id: Base64url;
  slip: Fingerprint;
  seq: number;
  previous?: Fingerprint;
  approval?: Fingerprint;
  terms?: Fingerprint;
  /** For a helper agent: the pass it acts under. */
  pass?: Fingerprint;
  when: Time;
}

/** A signed record: a JSON Web Signature in the general JSON serialisation. */
export interface SignedRecord {
  payload: Base64url;
  signatures: { protected: Base64url; signature: Base64url; header?: { authenticatorData: Base64url; clientDataJSON: Base64url } }[];
}

/** One entry of a book. */
export type BookEntry =
  | { slip: SignedRecord }
  | { stub: SignedRecord; countersignature?: SignedRecord; approval?: SignedRecord }
  | { refusal: SignedRecord }
  | { terms: SignedRecord }
  | { seal: SignedRecord; stamps?: StampItem[] }
  | { cancellation: SignedRecord; stamps?: StampItem[] }
  | { acknowledgement: SignedRecord }
  | { vouching: SignedRecord }
  | { withdrawal: SignedRecord }
  | { pass: SignedRecord };

export interface Show {
  type: 'provared.show.v0';
  size: number;
  root: Fingerprint;
  /** "disclosures" reveal covered fields of the record on that page. */
  pages: { index: number; entry: string; path: Fingerprint[]; disclosures?: string[] }[];
  seal?: { seal: SignedRecord; stamps?: StampItem[] };
}

// --- what the checker answers ---

export interface Finding {
  /** A fixed code in plain words, listed in docs/threat-model.md, section 8. */
  code: string;
  message: string;
}
export type SignatureState = 'valid' | 'invalid' | 'unavailable';
export interface KeySignature {
  method: string;
  state: SignatureState;
}
export interface Stamp {
  /** "service": a time-stamp from a time-stamp service. "block": a proof that leads to a block of a public blockchain. */
  kind: 'service' | 'block';
  /** "valid": from a service, or in a block, the checker named. "untrusted": sound, and not named. */
  state: 'valid' | 'untrusted' | 'unavailable' | 'invalid';
  /** The time the service, or the block, states. */
  when: Time | null;
  /** When the record existed by, in milliseconds. For a block: the stated time and two hours. */
  time: number;
  /** The earliest the time-stamp could have been made. For a block: the stated time less two hours. */
  earliest?: number;
  /** The fingerprint of the certificate of the service that signed, or of the block (64 hex characters). */
  authority: string | null;
  /** For a block: its number, as the proof states it. Nothing checks it. */
  height?: number;
}
/** A time-stamp beside a seal or a cancellation: a service's answer, or a proof with the header of its block. */
export type StampItem = Base64url | { block: Base64url; proof: Base64url };
/** Who vouches for a name, if anyone does. */
export type Vouched = { counted: boolean; by: string; keys: Fingerprint } | null;

export interface CheckedEntry {
  index: number;
  kind: 'slip' | 'stub' | 'refusal' | 'terms' | 'seal' | 'cancellation' | 'acknowledgement' | 'vouching' | 'withdrawal' | 'pass' | 'unreadable';
  fingerprint: Fingerprint | null;
  /** How much of the entry's own signing this device confirmed. */
  verified: 'all' | 'some' | 'none';
  /** Reasons the entry cannot be relied on. */
  problems: Finding[];
  /** What a sound entry shows about the agent. */
  breaches: Finding[];
  notes: string[];
  /**
   * What the entry says. Where the entry has problems, or "verified" is
   * "none", this is unverified: never show it as fact.
   */
  content?: any;
  /**
   * The time by which the entry is shown to have existed: the earliest that a counted time-stamp on a seal
   * after it states. Absent where no counted time-stamp covers the entry.
   */
  existedBy?: Time;
  /**
   * A seal or a cancellation: the time its own counted time-stamps give it. Absent where it has none, or
   * did not pass its check. (For a cancellation: the time it counts from.)
   */
  stampedAt?: Time;
  // A slip:
  /** The fields that are covered and were not revealed, for example "issuer.name". */
  covered?: string[];
  signature?: { method: string; alg: string | null; state: SignatureState | 'unchecked' };
  issuerKey?: string | null;
  /**
   * Who vouches for the names. On a slip: for the issuer, the agent, and
   * each service by its id (null where nobody does). On a seal or a pass:
   * for the recorder or the helper agent.
   */
  vouched?: { issuer: Vouched; agent: Vouched; services: Record<string, Vouched> } | Vouched;
  // A stub:
  slip?: Fingerprint;
  /** For a helper agent's stub: the pass it was written under. */
  pass?: Fingerprint;
  signatures?: KeySignature[];
  countersignature?: { state: 'absent' | 'unchecked' | SignatureState; signatures: KeySignature[]; when?: Time };
  approval?: { state: 'absent' | SignatureState; when?: Time; alg?: string };
  /** A stub, or a pass: whether it was compared with what it rests on. */
  compared?: boolean;
  needs?: ('approval' | 'countersignature')[];
  running?: { action: string; unit: string; total: string; max: number };
  // A refusal, terms, a seal, a vouching record, a withdrawal:
  signer?: Fingerprint;
  service?: string | null;
  sealer?: Fingerprint;
  stamps?: Stamp[];
  counted?: boolean;
}

export interface Summary {
  /** No problem was found and every signature was checked. The only answer that is a pass. */
  intact: boolean;
  problemFound: boolean;
  fullyChecked: boolean;
  /** The signing methods this device lacks, if any. */
  methodsMissing: string[];
  /** Every stub and every pass was compared with what it rests on, and none is outside it. */
  withinSlips: boolean;
  firstBreach: number | null;
  counts: {
    slips: number;
    stubs: number;
    countersigned: number;
    oneSided: number;
    approved: number;
    refusals: number;
    terms: number;
    seals: number;
    cancellations: number;
    acknowledgements: number;
    vouchings: number;
    passes: number;
  };
  /** How far the last time-stamp from a trusted service reaches. */
  sealed: { entries: number; when: Time; seal: number; by: 'service' | 'block' } | null;
  /** What no check can show, in plain sentences. */
  limits: string[];
}

/**
 * The person's own copy of a cancellation, as it is handed over: the entry it would be in a book, and with
 * it, where the person was given any, up to four acknowledgements from the agent's side.
 */
export interface HandedCancellation {
  cancellation: SignedRecord;
  stamps?: StampItem[];
  acknowledgements?: SignedRecord[];
}

/** The person's own copy of a cancellation, handed over beside the book. */
export interface HeldCancellation {
  kind: 'cancellation';
  fingerprint: Fingerprint | null;
  slip: Fingerprint | null;
  /** The entry of the book that holds the same cancellation, or null if the book leaves it out. */
  inBook: number | null;
  /** Whether it passed its check and was counted. */
  used: boolean;
  problems: Finding[];
  notes: string[];
  stamps: Stamp[];
  content?: any;
  signature?: { method: string; alg: string; state: SignatureState };
  /** The earliest time a time-stamp from a trusted service gives it. */
  stampedAt?: Time;
  /** The acknowledgements handed over with it: what the agent's side said about being handed it. */
  acknowledgements: HeldAcknowledgement[];
}
/** An acknowledgement handed over with the person's own copy of a cancellation. */
export interface HeldAcknowledgement {
  fingerprint: Fingerprint;
  /** Signed by the slip's own agent, or by a helper agent under a pass. */
  by: 'agent' | 'helper';
  pass: Fingerprint | null;
  state: 'valid' | 'unavailable';
  signatures: KeySignature[];
  /** When the agent's side says it was handed the cancellation: its own word. Null where this device could not check who signed. */
  when: Time | null;
  /** The entry of the book that holds the same acknowledgement, or null. */
  inBook: number | null;
}

export interface CheckResult {
  format: string;
  size: number;
  root: Fingerprint | null;
  problems: Finding[];
  notes: string[];
  entries: CheckedEntry[];
  /** What was handed over beside the book, and what came of it. */
  held: HeldCancellation[];
  summary: Summary;
}

export interface CheckOptions {
  /** The thumbprints of the issuer keys the checker expects. */
  issuerKeys?: string[];
  /** The key set fingerprints of the recorders the checker expects. */
  sealKeys?: Fingerprint[];
  /** The certificate fingerprints of the time-stamp services the checker trusts. */
  stampServices?: Fingerprint[];
  /** The fingerprints (64 hex characters) of the blocks of a public blockchain that the checker trusts to be part of the chain. */
  blocks?: string[];
  /** The key set fingerprints of the organisations whose vouching the checker trusts. */
  vouchers?: Fingerprint[];
  /** For covered fields: the disclosures handed over, by the fingerprint of the slip they belong to. */
  disclosures?: Record<Fingerprint, string[]>;
  /**
   * The person's own copies of cancellations, each as the entry it would
   * be in a book. At most 16. They count even where the book leaves them
   * out, or holds them with a later time-stamp.
   */
  cancellations?: HandedCancellation[];
  expectedRoot?: Fingerprint;
  expectedSize?: number;
  /** Signing methods to treat as not built into this device. It can only withhold a pass. */
  withoutMethods?: string[];
}

export interface SlipCheck {
  kind: 'slip';
  fingerprint: Fingerprint | null;
  problems: Finding[];
  notes: string[];
  signature: { method: string; alg: string | null; state: SignatureState | 'unchecked' };
  issuerKey: string | null;
  content: SlipContent | null;
  covered: string[];
  /**
   * Why the disclosures handed over were not used, if they were not. The
   * slip is then checked with those fields covered.
   */
  disclosureProblems: Finding[];
}

// --- checking ---

export function checkBook(text: string, options?: CheckOptions): Promise<CheckResult>;
/**
 * A checker that can be carried on: it reads a book once, and then takes more lines as the book grows,
 * without reading the earlier lines again. Its answer is the answer checkBook gives for the same text.
 */
export interface Checker {
  /** Takes more whole lines, each ending with a line feed. */
  add(text: string): Promise<void>;
  /** The answer for the book so far: a copy of its own each time. */
  result(): Promise<CheckResult>;
}
/** The options are fixed when the checker is opened. The book so far may be empty. */
export function openChecker(text?: string, options?: CheckOptions): Promise<Checker>;
export function checkShow(show: Show | string, options?: CheckOptions): Promise<CheckResult>;
export function checkSlip(record: SignedRecord, options?: Pick<CheckOptions, 'issuerKeys' | 'withoutMethods' | 'disclosures'>, disclosures?: string[]): Promise<SlipCheck>;
export function methodAvailable(alg: string): Promise<boolean>;
export function thumbprint(key: PublicKey): Promise<string>;
export function keySetFingerprint(keys: KeySet | SealKeySet): Promise<Fingerprint>;
/** The fingerprint of a block, as it is written everywhere: 64 hex characters. */
export function blockFingerprint(header: Uint8Array): Promise<string>;
/** A chain of Bitcoin block headers, checked on this device from the chain's first block. */
export interface HeaderChain {
  /** The number of the latest block. */
  height: number;
  /** Its fingerprint, 64 hex characters. */
  tip: string;
  /** The time it states. */
  tipWhen: Time;
  /** A block's number, and how many blocks come after it in this chain; null where the chain does not hold it. */
  find(fingerprint: string): { height: number; after: number } | null;
}
/** Check a chain of block headers held in a file. Throws a Refusal "headers-invalid" at the first header that breaks a rule. */
export function checkHeaderChain(bytes: Uint8Array, options?: { now?: number }): Promise<HeaderChain>;
/** The blocks a check's block time-stamps lead to that a checked chain holds with at least MIN_BLOCKS_AFTER blocks after them. */
export function blocksInChain(
  result: CheckResult,
  chain: Pick<HeaderChain, 'find'>,
): { blocks: string[]; found: { block: string; stated: number; height: number | null; after: number | null; counted: boolean }[] };
/** A block counts as part of the chain only with at least this many blocks after it. */
export const MIN_BLOCKS_AFTER: number;
export function limitWords(limit: Limit): string;
export function conditionWords(condition: Condition): string;
export function neverWords(name: string): string;
export const LIMITS: string[];
export const REFUSAL_REASONS: Record<string, string>;

export interface Proposal extends Request {
  slip: Fingerprint;
  pass?: Fingerprint;
  approval?: SignedRecord;
  terms?: Fingerprint;
  when?: number | Date;
}
export interface BeforeAnswer {
  allowed: boolean;
  problems: Finding[];
  breaches: Finding[];
  needs: ('approval' | 'countersignature')[];
}
/** "issuerKeys" must be given: a slip signed by any other key allows nothing. */
export function checkBefore(book: string, proposal: Proposal, options: CheckOptions & { issuerKeys: string[] }): Promise<BeforeAnswer>;

/** The stub writer beside an agent: ask first, act, write the stub. */
export interface Recorder {
  before(request: Request, more?: { when?: number | Date; terms?: Fingerprint; approval?: { record: SignedRecord } }): Promise<BeforeAnswer>;
  record(
    request: Request,
    more?: { when?: number | Date; terms?: Fingerprint; approval?: { record: SignedRecord }; countersign?: (stub: SignedRecord) => Promise<SignedRecord | null> },
  ): Promise<WrittenStub>;
  /**
   * If the action is not allowed it is not taken and nothing is written. Calls wait for one another.
   * The action is taken now: "when" defaults to the clock and must be within 300 seconds of it.
   */
  act<T>(
    request: Request,
    perform: () => Promise<T>,
    more?: { when?: number | Date; terms?: Fingerprint; approval?: { record: SignedRecord }; countersign?: (stub: SignedRecord) => Promise<SignedRecord | null> },
  ): Promise<{ done: boolean; answer: BeforeAnswer; result?: T; stub?: WrittenStub }>;
  book(): string;
  /**
   * What the record shows as it stands: the answer a whole check of the book gives, with the cancellations
   * the writer holds beside it. Nothing is read again. A copy of its own each time.
   */
  check(): Promise<CheckResult>;
  /**
   * The person's cancellations the writer holds beside its book: those it was given when opened, and those of
   * its own slip that it could not yet write into the book, each with the acknowledgement the writer signed
   * for it; and a cancellation whose acknowledgement still waits to follow it into the book, with that
   * acknowledgement. Keep them with the book, and hand them in again ("options.cancellations") when a
   * writer is opened again from it.
   */
  cancellations(): HandedCancellation[];
  /**
   * Adds an entry someone else made, only if the book still passes its check with it. A cancellation that
   * cannot be added as it was handed over is added by itself where that passes, or kept beside the book if
   * the person signed it for this writer's slip; the call still fails, and the error says what was done.
   * For the person's cancellation of this writer's own slip, the writer signs an acknowledgement, to be
   * given to the person: it is in the answer, or in the "acknowledgement" member of the error.
   */
  add(entry: BookEntry): Promise<{ acknowledgement?: SignedRecord }>;
}
/** A stub the stub writer wrote. A countersignature that did not check is left out, and "problem" says why. */
export type WrittenStub = Written & { seq: number; line: string; countersignature: { accepted: boolean; problem: Finding | null } };
export function openRecorder(o: {
  book: string;
  slip: Fingerprint;
  privateKeys: CryptoKey[];
  issuerKeys: string[];
  pass?: Fingerprint;
  options?: CheckOptions;
  /** The clock, in milliseconds. Defaults to the device's. "act" takes an action at its time, and nothing is written dated more than 300 seconds ahead of it. */
  now?: () => number;
  /** How long the other side is given to countersign, in milliseconds. Defaults to 30,000. */
  countersignWithin?: number;
}): Promise<Recorder>;

/** One of an agent's tools, as it is described to recordTools. */
export interface RecordedTool<A = any, R = any> {
  /** The action name the slip uses for what this tool does. */
  action: string;
  /** The tool itself. It must not call the stub writer. */
  run: (args: A) => R | Promise<R>;
  /** The id of the service the tool deals with, as the slip names it. */
  with?: string | ((args: A) => string | undefined);
  amount?: Amount | ((args: A) => Amount | undefined);
  /** The documents to name in the stub, or false for none. By default: "arguments", the fingerprint of the arguments. */
  details?: false | ((args: A) => DocumentRef[] | Promise<DocumentRef[]>);
  /** Asks the other side to countersign the stub. */
  countersign?: (stub: SignedRecord, args: A) => Promise<SignedRecord | null>;
  /** Asks the person for their approval, where the slip asks for one. */
  approve?: (request: Request, args: A) => Promise<{ record: SignedRecord } | null | undefined>;
}
/** A call through a recorded tool that was not run. "answer" is what the check before acting said. */
export class NotTaken extends Error {
  constructor(tool: string, answer: BeforeAnswer);
  tool: string;
  answer: BeforeAnswer;
}
/**
 * Puts an agent's tools behind the stub writer: each call asks first, runs the tool only if the slip allows
 * the action, and writes the stub. A call that is not allowed throws NotTaken, and the tool is not run.
 */
export function recordTools<T extends Record<string, RecordedTool>>(
  recorder: Recorder,
  tools: T,
  options?: { onStub?: (stub: WrittenStub, tool: string) => void | Promise<void> },
): { [K in keyof T]: (args?: Parameters<T[K]['run']>[0]) => Promise<Awaited<ReturnType<T[K]['run']>>> };
/** The fingerprint of the arguments of a call: SHA-256 of the arguments written in the one form of RFC 8785. */
export function argumentsFingerprint(args: unknown): Promise<Fingerprint>;

// --- writing ---

export interface Prepared {
  contentBytes: Uint8Array;
  payloadB64: Base64url;
  protectedB64: Base64url;
  /** What the person's passkey must sign. */
  challenge: Uint8Array;
}
export interface Assertion {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
}
export interface Written {
  record: SignedRecord;
  fingerprint: Fingerprint;
}

/** The fields of a slip that may be covered. */
export const COVERABLE: string[];
/** "disclosures" reveal the covered fields: keep them beside the slip, and hand over only the ones a reader needs. */
export function prepareSlip(fields: SlipFields, options?: { cover?: string[] }): Promise<Prepared & { disclosures: string[] }>;
export function assembleSlip(prepared: Pick<Prepared, 'payloadB64' | 'protectedB64'>, assertion: Assertion): SignedRecord;
export function prepareApproval(fields: Request & { slip: Fingerprint; when?: number | Date; id?: Base64url }): Promise<Prepared & { fingerprint: Fingerprint }>;
export function assembleApproval(prepared: Pick<Prepared, 'payloadB64' | 'protectedB64'>, assertion: Assertion): SignedRecord;
export function prepareCancellation(fields: { slip: Fingerprint; when?: number | Date; id?: Base64url }): Promise<Prepared & { fingerprint: Fingerprint }>;
export function assembleCancellation(prepared: Pick<Prepared, 'payloadB64' | 'protectedB64'>, assertion: Assertion): SignedRecord;

export function writeStub(
  fields: Request & {
    slip: Fingerprint;
    after: { seq: number; fingerprint: Fingerprint } | null;
    approval?: Fingerprint;
    terms?: Fingerprint;
    pass?: Fingerprint;
    when?: number | Date;
    id?: Base64url;
  },
  privateKeys: CryptoKey[],
): Promise<Written & { seq: number }>;
/** An agent hands part of its permission to a helper agent. */
export function writePass(
  fields: { slip: Fingerprint; from?: Fingerprint; to: Party; actions: string[]; limits?: Limit[]; validFrom: Time; validUntil: Time; when?: number | Date; id?: Base64url },
  privateKeys: CryptoKey[],
): Promise<Written>;
export function countersign(stub: SignedRecord, privateKeys: CryptoKey[], when?: number | Date): Promise<SignedRecord>;
export function writeRefusal(
  fields: { slip: Fingerprint; by: Party; action: string; amount?: Amount; reason: string; when?: number | Date; id?: Base64url },
  privateKeys: CryptoKey[],
): Promise<Written>;
export function writeTerms(
  fields: { by: Party; accepts: string[]; never?: string[]; validFrom: Time; validUntil: Time; id?: Base64url },
  privateKeys: CryptoKey[],
): Promise<Written>;
export type VouchedFor =
  | { kind: 'person'; key: PasskeyKey; name: string }
  | { kind: 'agent' | 'service'; keys: KeySet; name: string }
  | { kind: 'recorder'; keys: SealKeySet; name: string };
export function writeVouching(
  fields: { by: Party; for: VouchedFor; validFrom: Time; validUntil: Time; when?: number | Date; id?: Base64url },
  privateKeys: CryptoKey[],
): Promise<Written>;
export function writeWithdrawal(fields: { vouching: Fingerprint; when?: number | Date; id?: Base64url }, privateKeys: CryptoKey[]): Promise<Written>;
/** The agent's side states that it was handed the person's cancellation of a slip, and when. */
export function writeAcknowledgement(
  fields: { slip: Fingerprint; cancellation: Fingerprint; pass?: Fingerprint; when?: number | Date; id?: Base64url },
  privateKeys: CryptoKey[],
): Promise<Written>;
/** It needs Node.js: no browser has the seal's third signing method. */
export function writeSeal(
  book: string,
  fields: { by: { keys: SealKeySet; name: string }; previous?: Fingerprint; when?: number | Date; id?: Base64url },
  privateKeys: unknown[],
): Promise<Written & { fingerprintBytes: Uint8Array }>;

/** A proof from a public blockchain and the 80-byte header of its block, in the form they have in "stamps". */
export function blockStampItem(proof: Uint8Array, header: Uint8Array): { block: Base64url; proof: Base64url };

export function entryLine(entry: BookEntry): string;
export function writeBook(entries: BookEntry[]): string;
export function makeShow(text: string, indexes: number[], options?: { seal?: number; disclosures?: Record<number, string[]> }): Promise<Show>;

// --- keys and small tools ---

export function generateKeySet(): Promise<{ keys: KeySet; privateKeys: CryptoKey[] }>;
export function generateSealKeySet(): Promise<{ keys: SealKeySet; privateKeys: unknown[] }>;
export function fingerprint(contentBytes: Uint8Array): Promise<Fingerprint>;
export function sha256(bytes: Uint8Array): Promise<Uint8Array>;
export function formatTime(when: number | Date): Time;
export function randomId(): Base64url;
export function toBase64url(bytes: Uint8Array): Base64url;
export function fromBase64url(text: Base64url): Uint8Array;
export function utf8(text: string): Uint8Array;

// --- the shared list ---

export const RESERVED_PREFIX: 'provared.';
export const ACTION_KINDS: Record<string, string>;
export const SHARED_ACTIONS: Record<string, [kind: string, meaning: string]>;
export const CONDUCT_RULES: Record<string, string>;
export const VOUCHED_KINDS: Record<string, string>;
export function actionKind(name: string): string | null;
