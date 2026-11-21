// Money as whole numbers. A tool takes an amount as a whole number of the
// currency's smallest unit (1250 for 12.50 GBP), because a Provared
// permission limits whole numbers and the guard reads the amount of a call
// as the whole number at one place in its arguments. Shopify's Admin API
// takes and gives money as a decimal string ("12.50"). This file turns one
// into the other, exactly, with no floating-point arithmetic.
//
// How many decimal places a currency has is taken from ISO 4217 (its
// "minor unit"). A currency not in the table below is refused: guessing
// its places could move a decimal point.

const PLACES = new Map();
// No decimal places.
for (const c of 'BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF'.split(' ')) PLACES.set(c, 0);
// Three decimal places.
for (const c of 'BHD IQD JOD KWD LYD OMR TND'.split(' ')) PLACES.set(c, 3);
// Four decimal places.
for (const c of 'CLF UYW'.split(' ')) PLACES.set(c, 4);
// Two decimal places.
for (const c of ('AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BMD BND BOB BRL BSD BTN BWP BYN BZD '
  + 'CAD CDF CHF CNY COP CRC CUP CVE CZK DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD GTQ GYD '
  + 'HKD HNL HTG HUF IDR ILS INR IRR JMD KES KGS KHR KPW KYD KZT LAK LBP LKR LRD LSL MAD MDL MGA MKD MMK '
  + 'MNT MOP MRU MUR MVR MWK MXN MYR MZN NAD NGN NIO NOK NPR NZD PAB PEN PGK PHP PKR PLN QAR RON RSD RUB '
  + 'SAR SBD SCR SDG SEK SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TOP TRY TTD TWD TZS UAH USD '
  + 'UYU UZS VED VES WST XCD XCG YER ZAR ZMW ZWG').split(' ')) PLACES.set(c, 2);

/** How many decimal places a currency has (ISO 4217), or null for a currency this file does not know. */
export function places(currency) {
  return typeof currency === 'string' && PLACES.has(currency) ? PLACES.get(currency) : null;
}

/** Whether a value is a whole number of smallest units a tool takes: from 0 up to 9,007,199,254,740,991. */
export function isMinor(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

/** A whole number of smallest units as Shopify's decimal string: 1250 in GBP is "12.50". Null for a currency not known. */
export function toDecimal(minor, currency) {
  const p = places(currency);
  if (p === null || !isMinor(minor)) return null;
  const digits = String(minor).padStart(p + 1, '0');
  return p === 0 ? digits : `${digits.slice(0, -p)}.${digits.slice(-p)}`;
}

/**
 * Shopify's decimal string as a whole number of smallest units: "12.5" in
 * GBP is 1250. Null where the text is not a plain decimal, the currency is
 * not known, or the amount has more places than the currency (so that
 * nothing is rounded).
 */
export function toMinor(decimal, currency) {
  const p = places(currency);
  if (p === null || typeof decimal !== 'string') return null;
  // Digits, or digits, a full stop and digits; nothing else.
  const parts = decimal.split('.');
  if (parts.length > 2 || !/^\d{1,16}$/.test(parts[0]) || (parts.length === 2 && !/^\d{1,9}$/.test(parts[1]))) return null;
  const fraction = parts[1] ?? '';
  if (fraction.length > p && /[1-9]/.test(fraction.slice(p))) return null;
  const minor = Number(parts[0] + fraction.slice(0, p).padEnd(p, '0'));
  return isMinor(minor) ? minor : null;
}

/** Money as a tool's answer shows it: the decimal text, the same amount in smallest units, and the currency. */
export function shown(money) {
  if (!money || typeof money.amount !== 'string' || typeof money.currencyCode !== 'string') return null;
  return { amount: money.amount, amount_minor: toMinor(money.amount, money.currencyCode), currency: money.currencyCode };
}
