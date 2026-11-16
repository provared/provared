// Asking a time-stamp service for a time-stamp over a seal's fingerprint (RFC 3161). Network code, apart from the library.

/** How long one request may take, unless the caller says otherwise: milliseconds. */
export declare const STAMP_TIMEOUT_MS: number;
/** The least and the most time limit a caller may give: milliseconds. */
export declare const STAMP_TIMEOUT_MIN_MS: number;
export declare const STAMP_TIMEOUT_MAX_MS: number;
/** The largest answer read, in bytes. */
export declare const MAX_REPLY_BYTES: number;
/** The furthest the time a time-stamp states may be from this device's clock, in milliseconds. */
export declare const STAMP_CLOCK_GAP_MS: number;
/** How many random bytes the number used once holds. */
export declare const NONCE_BYTES: number;

/** The request of RFC 3161, section 2.4.1, in DER. */
export declare function stampRequest(fingerprintBytes: Uint8Array, nonce: Uint8Array): Uint8Array;

/** The address of a time-stamp service, read: http: or https:, no user name, password or fragment. */
export declare function stampAddress(address: string): string;

export interface StampOptions {
  /** The service's address; none is named by this package. */
  address: string;
  /** How long the whole request may take, in milliseconds (10,000). */
  timeout?: number;
  /** This device's clock, in milliseconds. */
  clock?: () => number;
}

/** Ask a service for a time-stamp over a seal's fingerprint, and check it. Throws a Refusal ("stamp-not-given", or a code of checkStamp). */
export declare function askForStamp(fingerprintBytes: Uint8Array, options: StampOptions): Promise<{ stamp: string; when: string; time: number; authority: string }>;

/** The "stamp" of openSealer, for one service: gives the item of "stamps", the time-stamp in base64url. */
export declare function stampService(options: StampOptions): (fingerprintBytes: Uint8Array) => Promise<string>;
