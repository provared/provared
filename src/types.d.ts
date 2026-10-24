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

/**
 * A signer: a key held elsewhere (a key service, a hardware module) that signs on request. Wherever
 * "privateKeys" is taken, each item may be a key or a signer. A signer's key must be of the method of
 * its place, and, where the writer knows the key the record must be signed with, that key. Every
 * signature it gives is checked against its key before it is used.
 */
export interface Signer {
  /** The public key, in one of the shapes of the format description, section 3.8. */
  key: Ed25519Key | MlDsaKey | SlhDsaKey;
  /** The signature over exactly these bytes: 64 bytes for Ed25519, 4,627 for ML-DSA-87, 29,792 for SLH-DSA-SHA2-256s. */
  sign(data: Uint8Array): Promise<Uint8Array | ArrayBuffer>;
}
/** A private key of the platform (a Web Crypto CryptoKey), or a signer. */
export type SigningKey = CryptoKey | Signer;

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
  | { seal: SignedRecord; stamps?: StampItem[]; witnesses?: SignedRecord[] }
  | { cancellation: SignedRecord; stamps?: StampItem[] }
  | { acknowledgement: SignedRecord }
  | { denial: SignedRecord }
  | { vouching: SignedRecord }
  | { withdrawal: SignedRecord }
  | { pass: SignedRecord };

export interface Show {
  type: 'provared.show.v0';
  size: number;
  root: Fingerprint;
  /** "disclosures" reveal covered fields of the record on that page. */
  pages: { index: number; entry: string; path: Fingerprint[]; disclosures?: string[] }[];
  seal?: { seal: SignedRecord; stamps?: StampItem[]; witnesses?: SignedRecord[] };
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
/** A witness statement beside a seal, as the checker found it (format description, section 29). */
export interface WitnessCheck {
  /** The statement's own fingerprint. */
  fingerprint: Fingerprint | null;
  /** The fingerprint of the witness's key set: how the person names a witness they trust. */
  witness: Fingerprint | null;
  /** The witness's name, a label. */
  name: string | null;
  /** When the witness says it signed: its own word. */
  when: Time | null;
  /** "valid": it passed its check and both its signatures were checked here. "unavailable": this device could not check them both. */
  state: 'valid' | 'unavailable' | 'invalid';
  /** Whether its witness is one the person named. */
  trusted: boolean;
  /**
   * Whether it counts: valid, trusted, its seal passed its own check with its first two signatures checked here, the book
   * starts with a permission signed by a passkey you named, you named the recorders you expect, and every permission the
   * seal covers names the first line's passkey and agent (a Show must hold every page the seal covers). Section 29.2.
   */
  counted: boolean;
  signatures: KeySignature[];
}
/** A time-stamp beside a seal or a cancellation: a service's answer, or a proof with the header of its block. */
export type StampItem = Base64url | { block: Base64url; proof: Base64url };
/** Who vouches for a name, if anyone does. */
export type Vouched = { counted: boolean; by: string; keys: Fingerprint } | null;

export interface CheckedEntry {
  index: number;
  kind: 'slip' | 'stub' | 'refusal' | 'terms' | 'seal' | 'cancellation' | 'acknowledgement' | 'vouching' | 'withdrawal' | 'pass' | 'denial' | 'unreadable';
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
  /** A seal: the witness statements on its line. */
  witnesses?: WitnessCheck[];
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
    denials: number;
    vouchings: number;
    passes: number;
  };
  /** How far the last time-stamp from a trusted service reaches. */
  sealed: { entries: number; when: Time; seal: number; by: 'service' | 'block' } | null;
  /**
   * How far a witness the person named reaches: the latest seal for which a statement counts, the entries it covers,
   * the witnesses whose statements count for it, and every seal for which one counts. Null where none does, or where a
   * problem was found. It excuses nothing.
   */
  witnessed: { seal: number; entries: number; by: Fingerprint[]; seals: number[] } | null;
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

/** A seal held elsewhere, as it is handed over: the entry it is in the book. */
export interface HandedSeal {
  seal: SignedRecord;
  stamps?: StampItem[];
  /** Witness statements for the seal, 1 to 4, none from one witness twice: those beside it in the book, or that came later. */
  witnesses?: SignedRecord[];
}

/**
 * A seal held elsewhere (by the person, an auditor, a copy kept apart), handed over beside the book. The book
 * must hold the same seal at the place it states: a book that ends before that place was cut short
 * ("book-cut-short"), and one that holds another line there was changed ("seal-not-in-book").
 */
export interface HeldSeal {
  kind: 'seal';
  fingerprint: Fingerprint | null;
  /** The fingerprint of the key set that signed it. */
  sealer: Fingerprint | null;
  /** The entry of the book at which it stands: the number of entries it covers. Null where it could not be read. */
  place: number | null;
  /** That entry, where the book holds the same seal there; null otherwise, or where it was not used. */
  inBook: number | null;
  /**
   * Whether it was compared with the book: it passed its check, its recorder is one you named, this device checked its
   * first two signatures, and it gives the book's own number (section 21.6). One that was not compared gives no pass.
   */
  used: boolean;
  verified: 'all' | 'some' | 'none';
  problems: Finding[];
  notes: string[];
  signatures: KeySignature[];
  /** Its own time-stamps: checked and shown, not used for the entries of the book. */
  stamps: Stamp[];
  /** The witness statements handed over with it. One that counts, for a seal the book holds at its place, counts for that seal. */
  witnesses: WitnessCheck[];
  content?: any;
  /** The earliest time a time-stamp from a trusted service gives it, where all three of its signatures were checked. */
  stampedAt?: Time;
}

export interface CheckResult {
  format: string;
  size: number;
  root: Fingerprint | null;
  problems: Finding[];
  notes: string[];
  entries: CheckedEntry[];
  /** What was handed over beside the book, and what came of it: the cancellations first, then the seals. */
  held: (HeldCancellation | HeldSeal)[];
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
  /** The key set fingerprints of the witnesses the checker trusts (format description, section 29). */
  witnesses?: Fingerprint[];
  /** For covered fields: the disclosures handed over, by the fingerprint of the slip they belong to. */
  disclosures?: Record<Fingerprint, string[]>;
  /**
   * The person's own copies of cancellations, each as the entry it would
   * be in a book. At most 16. They count even where the book leaves them
   * out, or holds them with a later time-stamp.
   */
  cancellations?: HandedCancellation[];
  /**
   * Seals held elsewhere, each as the entry it is in the book. At most 64. The book must hold each at the
   * place it states. Each counts only where its recorder is one named in "sealKeys".
   */
  seals?: HandedSeal[];
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
/**
 * Check a consistency proof (RFC 9162, section 2.1.4.2): that the tree of m leaves whose root is rootM is the first
 * part of the tree of n leaves whose root is rootN. For m equal to n the proof is empty and the roots the same; for
 * m of 0 the proof is empty and rootM the root of the empty tree. Never throws for a bad proof.
 */
export function verifyConsistency(m: number, n: number, rootM: Uint8Array, rootN: Uint8Array, proof: Uint8Array[]): Promise<boolean>;
/** Check an audit path (RFC 9162, section 2.1.3.2). */
export function verifyInclusion(index: number, size: number, leaf: Uint8Array, path: Uint8Array[], root: Uint8Array): Promise<boolean>;
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
/** Who said no, in a denial: "check", "person" or "rule", each with its meaning. */
export const DENIAL_SOURCES: Record<'check' | 'person' | 'rule', string>;

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
  /** Present only where the device went on without checking a seal's third signature (SLH-DSA-SHA2-256s): the methods not checked. */
  notChecked?: string[];
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
    more?: {
      when?: number | Date;
      terms?: Fingerprint;
      approval?: { record: SignedRecord };
      countersign?: (stub: SignedRecord) => Promise<SignedRecord | null>;
      /**
       * Up to four further documents, from what the action gave back. The stub is then signed after the action,
       * in the same turn, and keeps the time the action began. The request may then name at most 28 documents,
       * and no approval may be given. If it fails, the stub is written without them, and "detailsAfter" in the
       * answer says why.
       */
      detailsAfter?: (result: T) => DocumentRef[] | null | undefined | Promise<DocumentRef[] | null | undefined>;
      /** False writes no denial for this call, where the writer was opened with "denials: true". */
      denial?: boolean;
    },
  ): Promise<{ done: boolean; answer: BeforeAnswer; result?: T; stub?: WrittenStub; detailsAfter?: { added: number; problem: Finding | null }; denial?: DenialAnswer }>;
  /**
   * Writes a denial for an action that was not taken where "act" wrote none: the person said no, a rule of the
   * software around the agent said no, or ("check", with the codes of that answer) the check before acting said no
   * on a call for which "act" was asked to write none. A writer opened without "denials: true" writes none.
   */
  deny(request: Request, more: { source: 'check' | 'person' | 'rule'; codes?: string[]; when?: number | Date }): Promise<DenialAnswer>;
  /** Whether this writer writes denials, as it was opened. */
  readonly denials: boolean;
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
/**
 * What the stub writer did about a denial. "notWritten" counts the denials not written because of the hourly
 * limit since the writer was opened.
 */
export type DenialAnswer = { written: true; fingerprint: Fingerprint; line: string; notWritten: number } | { written: false; problem: Finding; notWritten: number };
/** A stub the stub writer wrote. A countersignature that did not check is left out, and "problem" says why. */
export type WrittenStub = Written & { seq: number; line: string; countersignature: { accepted: boolean; problem: Finding | null } };
export function openRecorder(o: {
  book: string;
  slip: Fingerprint;
  /** The agent's private keys, or signers: Ed25519, then ML-DSA-87. A signer must hold the keys the slip, or the pass, names. */
  privateKeys: SigningKey[];
  issuerKeys: string[];
  pass?: Fingerprint;
  options?: CheckOptions;
  /** The clock, in milliseconds. Defaults to the device's. "act" takes an action at its time, and nothing is written dated more than 300 seconds ahead of it. */
  now?: () => number;
  /** How long the other side is given to countersign, in milliseconds. Defaults to 30,000. */
  countersignWithin?: number;
  /** How long a signer is given for each signature, in milliseconds. Defaults to 30,000. After that nothing is written. */
  signWithin?: number;
  /** True to write a denial whenever "act" does not take an action, and to let "deny" write one. Defaults to false. */
  denials?: boolean;
  /** The most denials written in any hour, by the clock: 1 to 100,000. Defaults to 600. */
  denialsPerHour?: number;
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
  /** The documents to name in the stub, or false for none. By default: "provared.arguments", the fingerprint of the arguments. */
  details?: false | ((args: A) => DocumentRef[] | Promise<DocumentRef[]>);
  /** Asks the other side to countersign the stub. */
  countersign?: (stub: SignedRecord, args: A) => Promise<SignedRecord | null>;
  /** Asks the person for their approval, where the slip asks for one. */
  approve?: (request: Request, args: A) => Promise<{ record: SignedRecord } | null | undefined>;
}
/** A call through a recorded tool that was not run. "answer" is what the check before acting said. */
export class NotTaken extends Error {
  constructor(tool: string, answer: BeforeAnswer, denial?: DenialAnswer);
  tool: string;
  answer: BeforeAnswer;
  /** Where the stub writer writes denials: what it did about the denial for this call. */
  denial?: DenialAnswer;
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
  privateKeys: SigningKey[],
): Promise<Written & { seq: number }>;
/** An agent hands part of its permission to a helper agent. */
export function writePass(
  fields: { slip: Fingerprint; from?: Fingerprint; to: Party; actions: string[]; limits?: Limit[]; validFrom: Time; validUntil: Time; when?: number | Date; id?: Base64url },
  privateKeys: SigningKey[],
): Promise<Written>;
export function countersign(stub: SignedRecord, privateKeys: SigningKey[], when?: number | Date): Promise<SignedRecord>;
export function writeRefusal(
  fields: { slip: Fingerprint; by: Party; action: string; amount?: Amount; reason: string; when?: number | Date; id?: Base64url },
  privateKeys: SigningKey[],
): Promise<Written>;
export function writeTerms(
  fields: { by: Party; accepts: string[]; never?: string[]; validFrom: Time; validUntil: Time; id?: Base64url },
  privateKeys: SigningKey[],
): Promise<Written>;
export type VouchedFor =
  | { kind: 'person'; key: PasskeyKey; name: string }
  | { kind: 'agent' | 'service'; keys: KeySet; name: string }
  | { kind: 'recorder'; keys: SealKeySet; name: string };
export function writeVouching(
  fields: { by: Party; for: VouchedFor; validFrom: Time; validUntil: Time; when?: number | Date; id?: Base64url },
  privateKeys: SigningKey[],
): Promise<Written>;
export function writeWithdrawal(fields: { vouching: Fingerprint; when?: number | Date; id?: Base64url }, privateKeys: SigningKey[]): Promise<Written>;
/** The agent's side states that it was handed the person's cancellation of a slip, and when. */
export function writeAcknowledgement(
  fields: { slip: Fingerprint; cancellation: Fingerprint; pass?: Fingerprint; when?: number | Date; id?: Base64url },
  privateKeys: SigningKey[],
): Promise<Written>;
/** The format's own list of finding codes, from which a denial by the check before acting names its reasons. */
export const FINDING_CODES: readonly string[];
/** The reasons of a refusal by the check before acting, as a denial names them: 1 to 16 codes, each once. */
export function denialCodes(answer: Pick<BeforeAnswer, 'problems' | 'breaches'>): string[];
/** The agent's side states that it did not take an action that was asked for, and why. */
export function writeDenial(
  fields: Request & { slip: Fingerprint; pass?: Fingerprint; source: 'check' | 'person' | 'rule'; codes?: string[]; when?: number | Date; id?: Base64url },
  privateKeys: SigningKey[],
): Promise<Written>;
/**
 * It needs Node.js: no browser has the seal's third signing method. "privateKeys": the recorder's three keys (two
 * Web Crypto keys, and a Node.js KeyObject or what Node.js reads as one: PEM text, DER bytes with their format, or a
 * JSON Web Key with its format), or signers, each holding the key "by" names in its place.
 */
export function writeSeal(
  book: string,
  /** "book": the book's number among the books of one permission, 2 or more; 1 or none for the first (section 21.6). */
  fields: { by: { keys: SealKeySet; name: string }; previous?: Fingerprint; book?: number; when?: number | Date; id?: Base64url },
  privateKeys: unknown[],
): Promise<Written & { fingerprintBytes: Uint8Array }>;

/** The most witness statements beside one seal, or handed over with one seal held elsewhere. */
export const MAX_WITNESSES: 4;
/** A witness signs for a seal. This only writes the statement; it does not check the seal (see openWitness). */
export function writeWitness(
  fields: { seal: Fingerprint; size: number; root: Fingerprint; by: { keys: KeySet; name: string }; when?: number | Date; id?: Base64url },
  privateKeys: SigningKey[],
): Promise<Written>;
/** The consistency proof from the tree of the first m leaves to the tree of all of them (RFC 9162, section 2.1.4.1). Empty for m of 0 or m equal to the number of leaves. */
export function consistencyProof(leaves: Uint8Array[], m: number): Promise<Uint8Array[]>;
/** The audit path of one leaf (RFC 9162, section 2.1.3). */
export function inclusionPath(leaves: Uint8Array[], index: number): Promise<Uint8Array[]>;
/** How a witness keeps sequences of books apart: the recorder's key set, with the passkey and the agent's key set that the permission on the book's first line names. */
export function bookIdentity(keys: SealKeySet, firstLine: Uint8Array): Promise<Fingerprint>;
/**
 * What a witness is sent with a seal: the consistency proof from the seal it holds for the book ("from", its number
 * of entries), or, where it holds none or the seal is the first of the next book, the audit path of the book's first line in
 * the new seal's tree.
 */
export function witnessProof(book: string, size: number, from?: number | null): Promise<Uint8Array[]>;
/** A witness's state, as it hands it back: to be saved before a statement is given out. */
export interface WitnessState {
  type: 'provared.witness-state.v0';
  /** The fingerprint of the witness's key set. */
  by: Fingerprint;
  /** For each recorder, passkey (its thumbprint) and agent (the fingerprint of its key set): the latest seal this witness signed for, and its statement. */
  books: { passkey: Fingerprint; agent: Fingerprint; seal: SignedRecord; statement: SignedRecord }[];
}
export type WitnessAnswer<T> = T | { refused: Finding };
export interface Witness {
  /** Sign for a seal if it extends the latest seal of its book this witness holds. The state handed back holds the new seal: save it first. */
  witness(entry: { seal: SignedRecord; stamps?: StampItem[]; witnesses?: SignedRecord[] }, proof: Uint8Array[], firstLine: Uint8Array): Promise<WitnessAnswer<{ statement: SignedRecord; state: WitnessState }>>;
  /** Take as the latest seal of its book a seal this witness signed for before, from a copy of what it gave out. It signs nothing. */
  update(entry: { seal: SignedRecord; witnesses: SignedRecord[]; stamps?: StampItem[] }, proof: Uint8Array[], firstLine: Uint8Array): Promise<WitnessAnswer<{ state: WitnessState }>>;
  /** Opened from a saved state, the witness signs nothing until it is told it has been brought up to date. */
  ready(): void;
  latest(book: Fingerprint): { seal: SignedRecord; statement: SignedRecord } | null;
  state(): WitnessState;
}
/** A witness needs SLH-DSA, so it needs Node.js. */
export function openWitness(o: {
  by: { keys: KeySet; name: string };
  signers: SigningKey[];
  state?: WitnessState;
  clock?: () => number;
  withoutMethods?: string[];
}): Promise<Witness>;

/** The leaf fingerprint of one line of a book, without its line feed: SHA-256 of 0x00 and the line (RFC 6962, section 2.1). What a recorder sends a central sealer. */
export function leafFingerprint(line: string): Promise<Uint8Array>;
/** Which book a sealer call is about: the leaf fingerprint of its first line (a first book), or that with the book's number (section 21.6). */
export type SealerBook = Fingerprint | { first: Fingerprint; number?: number };
/** A central sealer's state, as it hands it back: to be saved before the answer is given out. At most 1,000 books. */
export interface SealerState {
  type: 'provared.sealer-state.v0';
  /** The fingerprint of the sealer's key set. */
  by: Fingerprint;
  /**
   * For each book: its first line's leaf fingerprint and number, the recorder it belongs to (absent for the sealer's own calls),
   * the book it follows, whether a later book follows it, and its latest seal with the tree's parts at that seal. A book is kept at
   * its latest seal, or with none at its first line: lines that no seal covers are asked for again after a start.
   */
  books: {
    first: Fingerprint;
    number: number;
    recorder?: string;
    follows?: Fingerprint;
    closed: boolean;
    /** The latest seal and its time-stamps (at most four); witness statements are never kept. */
    latest?: { entry: { seal: SignedRecord; stamps?: StampItem[] }; parts: Base64url[] };
  }[];
}
export type SealerAnswer<T> = T | { refused: Finding; size?: number };
/** The calls of a central sealer, made as one recorder (forRecorder) or as none (the sealer's own). */
export interface SealerCalls {
  /**
   * Take in the leaf fingerprints of new lines of one book, in order, from place "at" (the number of lines it holds). A later book
   * names the book it follows; a book whose first line the sealer holds starts only as the next book after the latest with that
   * first line. "line" is the book's first line itself: where any recorder has a list of agents, a book is started only with it,
   * and it must be a permission for an agent of the caller's own. Where the call started a book, the answer holds the state: save it first.
   */
  extend(book: SealerBook, at: number, leaves: Uint8Array[], more?: { follows?: Fingerprint; line?: string }): Promise<SealerAnswer<{ size: number; state?: SealerState }>>;
  /** Sign a seal over the tree this sealer holds; "previous" is the seal the new seal must name, as the book shows it. The state handed back holds the new seal: save it first. */
  seal(
    book: SealerBook,
    more: { previous: Fingerprint | null; when?: number | Date; id?: Base64url },
  ): Promise<SealerAnswer<{ entry: { seal: SignedRecord; stamps?: StampItem[] }; line: string; fingerprint: Fingerprint; fingerprintBytes: Uint8Array; state: SealerState; stampProblem?: Finding }>>;
  /**
   * Bring the sealer up to date for a book from a later seal it signed, with the leaf fingerprints from its own latest seal to that one.
   * Where it is the first seal of a later book, the book before is closed; where the sealer holds that book at an earlier seal than the
   * one named, it is refused until that book is brought up to date. A book it does not hold is started here under the same rules
   * as with extend, "line" included. It signs nothing. It keeps the seal, whose three signatures it checks, and its time-stamps
   * (at most four), read for their form only: no time-stamp's signature is checked. It keeps no witness statements; an entry longer
   * than a line of a book may be is refused (too-large). The entry is read once, and only that copy is used.
   */
  update(
    book: SealerBook,
    entry: { seal: SignedRecord; stamps?: StampItem[]; witnesses?: SignedRecord[] },
    leaves: Uint8Array[],
    more?: { line?: string },
  ): Promise<SealerAnswer<{ size: number; state: SealerState }>>;
  latest(book: SealerBook): { entry: { seal: SignedRecord; stamps?: StampItem[] }; line: string; fingerprint: Fingerprint } | null;
  held(book: SealerBook): { first: Fingerprint; number: number; follows: Fingerprint | null; size: number; closed: boolean; latest: Fingerprint | null; sealed: number } | null;
}
export interface Sealer extends SealerCalls {
  state(): SealerState;
  /**
   * The same calls for one named recorder (a label): its books, and every book after them, are its own. "rules": the fingerprints
   * of the key sets of the agents whose permissions it may start books with (1 to 64; an agent belongs to one recorder), and the
   * most books it may hold (1 to 1,000). A recorder's rules are fixed by the first call that gives them.
   */
  forRecorder(recorder: string, rules?: { agents?: Fingerprint[]; books?: number }): SealerCalls;
  /**
   * Take off the books that hold no seal (nothing was signed for them): every recorder's, or one recorder's (null for the sealer's
   * own calls). The state handed back is to be saved.
   */
  releaseUnsealed(o?: { recorder?: string | null }): Promise<{ released: { first: Fingerprint; number: number; recorder: string | null }[]; state: SealerState }>;
}
/** A central sealer: it seals books it is sent only the leaf fingerprints of. It checks every seal it signs, so it needs Node.js. */
export function openSealer(o: {
  by: { keys: SealKeySet; name: string };
  signers: unknown[];
  /** Ask a time-stamp service for a stamp over a seal's fingerprint: an item of "stamps", or null. */
  stamp?: (fingerprintBytes: Uint8Array) => Promise<StampItem | null> | StampItem | null;
  state?: SealerState;
  clock?: () => number;
  signWithin?: number;
}): Promise<Sealer>;

/** A proof from a public blockchain and the 80-byte header of its block, in the form they have in "stamps". */
export function blockStampItem(proof: Uint8Array, header: Uint8Array): { block: Base64url; proof: Base64url };

export function entryLine(entry: BookEntry): string;
export function writeBook(entries: BookEntry[]): string;
export function makeShow(text: string, indexes: number[], options?: { seal?: number; disclosures?: Record<number, string[]> }): Promise<Show>;

// --- keys and small tools ---

export function generateKeySet(): Promise<{ keys: KeySet; privateKeys: CryptoKey[] }>;
export function generateSealKeySet(): Promise<{ keys: SealKeySet; privateKeys: unknown[] }>;
/** A private key held in memory, wrapped as a signer: a CryptoKey, or for SLH-DSA-SHA2-256s a Node.js KeyObject. */
export function signerFromKey(alg: 'Ed25519' | 'ML-DSA-87' | 'SLH-DSA-SHA2-256s', privateKey: unknown, key: Ed25519Key | MlDsaKey | SlhDsaKey): Signer;
export function fingerprint(contentBytes: Uint8Array): Promise<Fingerprint>;
export function sha256(bytes: Uint8Array): Promise<Uint8Array>;
export function formatTime(when: number | Date): Time;
export function randomId(): Base64url;
export function toBase64url(bytes: Uint8Array): Base64url;
export function fromBase64url(text: Base64url): Uint8Array;
export function utf8(text: string): Uint8Array;

// --- the shared list ---

export const RESERVED_PREFIX: 'provared.';
/** Document names that begin with this are reserved: only those in DOCUMENT_NAMES may be used. */
export const RESERVED_DOCUMENT_PREFIX: 'provared.';
/** The reserved document names, and the exact text whose SHA-256 each one gives (format description, section 27). */
export const DOCUMENT_NAMES: Readonly<Record<string, string>>;
/** For "provared.http-request": the method and the address exactly as sent, and the body's bytes where there is a body. */
export function httpRequestFingerprint(r: { method: string; url: string; body?: Uint8Array }): Promise<Fingerprint>;
/** For "provared.http-response": the status code, and the body's bytes where there is a body. */
export function httpResponseFingerprint(r: { status: number; body?: Uint8Array }): Promise<Fingerprint>;
/** For "provared.trace-id", "provared.request-id", "provared.event-id" and "provared.error": SHA-256 of the text's UTF-8 bytes, exactly as given. */
export function identifierFingerprint(id: string): Promise<Fingerprint>;
export const ACTION_KINDS: Record<string, string>;
export const SHARED_ACTIONS: Record<string, [kind: string, meaning: string]>;
export const CONDUCT_RULES: Record<string, string>;
export const VOUCHED_KINDS: Record<string, string>;
export function actionKind(name: string): string | null;
