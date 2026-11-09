// How one line of a book is sealed for the server, the same in the browser
// and in the uploader beside the recorder. Web Crypto only, through the
// engine's crypto-core.
//
// Each line is sealed under the book's own key (K_object, from the engine's
// access model) with the book's id, the part and the line's place bound in
// as additional authenticated data. So a sealed line opens only in its own
// book, in its own part, at its own place: the server, which cannot read
// it, also cannot move it without the person noticing.
//
// PARTS. A recorder starts a new book file now and then (the recorder
// beside Claude Code does so at 90,000 entries): it keeps the old file as
// book-<n>.jsonl and starts book.jsonl again. The application keeps each
// file as a part of one book: part 0 is the first file the uploader
// followed, part 1 the next, and so on, each with places of its own from 0.
//
// Part 0 keeps the binding every line had before parts existed, so that
// the lines already on the server still open: "<namespace>/entry/v1", the
// book's id, the place. Parts 1 and on are bound with a label of their own,
// "<namespace>/entry/v2", the book's id, the part and the place. The two
// frames differ in their label and in their length, so a line sealed for
// one part never opens as a line of another.

export const NAMESPACE = 'provared-app';
export const COLLECTION = 'books';
export const ENTRY_PURPOSE = 'entry';
/** The highest part and the highest place a book may hold (a 32-bit signed number, as the database keeps them). */
export const MAX_PART = 2 ** 31 - 1;

/**
 * A line's bound context.
 *   part 0:     "<namespace>/entry/v1" ‖ 0x00 ‖ object id (16 bytes) ‖ place (4 bytes, big-endian)
 *   part 1 on:  "<namespace>/entry/v2" ‖ 0x00 ‖ object id (16 bytes) ‖ part (4 bytes) ‖ place (4 bytes)
 */
export function entryContext(cc, objectId, seq, part = 0) {
  if (!Number.isInteger(part) || part < 0 || part > MAX_PART) throw new Error('part out of range');
  if (part === 0) return cc.frameContext(cc.label(ENTRY_PURPOSE), cc.uuidBytes(objectId), cc.u32be(seq));
  return cc.frameContext(cc.label(ENTRY_PURPOSE, 2), cc.uuidBytes(objectId), cc.u32be(part), cc.u32be(seq));
}

/** Seals one line (text, without its newline) for the server, at a place of a part (part 0 when none is given). */
export async function sealEntry(cc, kObjectKey, objectId, seq, line, part = 0) {
  return cc.sealSymmetric(kObjectKey, new TextEncoder().encode(line), entryContext(cc, objectId, seq, part));
}

/** Opens one sealed line; throws if it was not sealed for this book, at this place of this part. */
export async function openEntry(cc, kObjectKey, objectId, seq, sealed, part = 0) {
  return new TextDecoder().decode(await cc.openSymmetric(kObjectKey, sealed, entryContext(cc, objectId, seq, part)));
}

/** The lines of a book's text, without empty lines. */
export function linesOf(text) {
  return text.split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l.length > 0);
}
