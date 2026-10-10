// Type declarations for "provared/dev": a development stand-in for a
// passkey. It is not a passkey, and no person confirms anything through
// it. Every slip it signs carries " (development)" in its issuer's name.

import type { Assertion, KeySet, Limit, Recorder, CheckOptions, Es256Key, Fingerprint, SignedRecord, SlipFields } from './types.js';

/** The words every development slip carries in its issuer's name: "(development)". */
export const DEVELOPMENT_MARK: string;

export interface DevelopmentPasskey {
  key: Es256Key;
  rpId: 'localhost';
  origin: 'http://localhost';
  /** The three values a passkey returns, for a challenge from prepareSlip, prepareApproval or prepareCancellation. */
  sign(challenge: Uint8Array): Promise<Assertion>;
}

/** A development stand-in for a passkey (ES256), signing for http://localhost. */
export function developmentPasskey(): Promise<DevelopmentPasskey>;

export interface DevelopmentSlip {
  slip: SignedRecord;
  slipFingerprint: Fingerprint;
  /** A book holding the slip alone: what openRecorder takes. */
  book: string;
  /** The thumbprint of the stand-in passkey, to hand to a checker as the passkey you trust. */
  issuerKeys: string[];
  agent: { keys: KeySet; privateKeys: CryptoKey[] };
  passkey: DevelopmentPasskey;
}

/**
 * The members of a development slip: as for prepareSlip, except that the
 * issuer's key and page address, and the agent's keys, are filled in.
 */
export type DevelopmentSlipFields = Omit<SlipFields, 'issuer' | 'agent' | 'validFrom' | 'validUntil' | 'purpose' | 'with' | 'limits'> & {
  issuer?: { name?: string };
  agent?: { name?: string; software?: SlipFields['agent']['software'] };
  /** Defaults to an empty list. */
  limits?: Limit[];
  validFrom?: string;
  validUntil?: string;
  purpose?: string;
  with?: SlipFields['with'];
};

/** A slip signed with a development stand-in for a passkey, with new keys for the agent. */
export function developmentSlip(fields: DevelopmentSlipFields): Promise<DevelopmentSlip>;

/** The stub writer opened under a development slip, in one call. */
export function developmentRecorder(
  fields: DevelopmentSlipFields,
  more?: { options?: CheckOptions; now?: () => number; countersignWithin?: number },
): Promise<Omit<DevelopmentSlip, 'book'> & { recorder: Recorder }>;
