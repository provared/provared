// Type declarations for the part of the library that asks a browser's
// passkey to sign. See types.d.ts.
import type { Assertion, Base64url, PasskeyKey, Request, SignedRecord, SlipFields, Fingerprint } from './types.js';

export class PasskeyError extends Error {
  code: string;
}
/** What must be kept to sign later: the passkey's identifier, its public key, and the website. */
export interface StoredPasskey {
  credentialId: string;
  key: PasskeyKey;
  rpId: string;
  origin: string;
}
export function createPasskey(o: { name: string; site: string }): Promise<StoredPasskey>;
export function signSlipWithPasskey(fields: Omit<SlipFields, 'issuer'>, passkey: StoredPasskey, issuerName: string): Promise<SignedRecord>;
export function approveWithPasskey(request: Request & { slip: Fingerprint; when?: number | Date }, passkey: StoredPasskey): Promise<SignedRecord>;
export function cancelWithPasskey(request: { slip: Fingerprint; when?: number | Date; id?: Base64url }, passkey: StoredPasskey): Promise<SignedRecord>;
/** Sign the challenge of anything prepared for a passkey; hand the result to the matching assemble function. */
export function signChallengeWithPasskey(challenge: Uint8Array, passkey: StoredPasskey): Promise<Assertion>;
