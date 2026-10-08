# A block time-stamp: proof that a fingerprint was written into a block of
# a public blockchain. The chain is used purely as a clock. No coin, no
# wallet, no account and no payment is involved, in making a proof or in
# checking one.
#
# The proof is a file of the open format "OpenTimestamps", version 1, as
# that format's reference reader accepts it, read strictly here. It is a
# list of steps that lead from the fingerprint to the Merkle root in the
# header of a block of the Bitcoin blockchain: join bytes before, join
# bytes after, take SHA-256. The block's own 80-byte header comes with the
# proof.
#
# Nothing here rests on a signature. It rests on SHA-256 (FIPS 180-4), and
# on the person checking having named the block as one they trust to be
# part of the chain.
#
# Format description, section 21.4.

from .encoding import Refusal, format_time, sha256, to_base64url

MAX_PROOF_BYTES = 12288
"""The largest proof accepted, in bytes: the same as for a time-stamp from a service."""

BLOCK_HEADER_BYTES = 80
"""The length of a block header, in bytes."""

BLOCK_TIME_ALLOWANCE_MS = 7200 * 1000
"""How far the time a block states may be from the true time: two hours.
A block's time is set by whoever made the block, within about that much."""

# The limits of the format's own reference reader.
_MAX_VALUE_BYTES = 4096
_MAX_ATTESTATION_BYTES = 8192
_MAX_DEPTH = 255

# How a proof file begins, and the mark of "this value is the Merkle root
# of a block of the Bitcoin blockchain".
_MAGIC = b'\x00' + b'OpenTimestamps' + b'\x00\x00' + b'Proof' + bytes([0x00, 0xBF, 0x89, 0xE2, 0xE8, 0x84, 0xE8, 0x92, 0x94])
_BLOCK_MARK = bytes([0x05, 0x88, 0x96, 0x0D, 0x73, 0xD7, 0x19, 0x01])

_SHA256 = 0x08
_JOIN_AFTER = 0xF0
_JOIN_BEFORE = 0xF1
_ATTESTATION = 0x00
_FORK = 0xFF


def _bad(why):
    return Refusal('stamp-bad-data', f'A block time-stamp is not laid out as its format sets out: {why}')


class _Reader:
    __slots__ = ('_data', '_at')

    def __init__(self, data):
        self._data = data
        self._at = 0

    def byte(self):
        if self._at >= len(self._data):
            raise _bad('it is cut short.')
        b = self._data[self._at]
        self._at += 1
        return b

    def take(self, length):
        if self._at + length > len(self._data):
            raise _bad('it is cut short.')
        self._at += length
        return self._data[self._at - length:self._at]

    def done(self):
        return self._at == len(self._data)


def _number(r, most):
    """A whole number as the format writes it: seven bits to a byte, lowest
    first, the top bit saying that another byte follows. Only the shortest
    form is accepted, so that one number has one form."""
    value = 0
    for i in range(5):
        b = r.byte()
        value += (b & 0x7F) * 2 ** (7 * i)
        if not (b & 0x80):
            if i > 0 and b == 0:
                raise _bad('a number is not written in its shortest form.')
            if value > most:
                raise _bad('a number is larger than the format allows.')
            return value
    raise _bad('a number is longer than the format allows.')


def _read_item(r, tag, value, found):
    """One thing that follows from a value: a statement about it, or a step
    that makes a new value. Returns the new value, or None after a statement."""
    if tag == _ATTESTATION:
        mark = r.take(8)
        payload = r.take(_number(r, _MAX_ATTESTATION_BYTES))
        # Statements of other kinds (a proof not yet complete, another chain) say nothing here.
        if mark != _BLOCK_MARK:
            return None
        p = _Reader(payload)
        height = _number(p, 2**35 - 1)
        if not p.done():
            raise _bad("the statement about a block holds more than the block's number.")
        if len(value) == 32:
            found.append({'root': value, 'height': height})
        return None
    if tag == _SHA256:
        return sha256(value)
    if tag == _JOIN_AFTER or tag == _JOIN_BEFORE:
        joined = r.take(_number(r, _MAX_VALUE_BYTES))
        if len(joined) == 0:
            raise _bad('a step joins nothing.')
        if len(value) + len(joined) > _MAX_VALUE_BYTES:
            raise _bad('a step makes a value longer than 4,096 bytes.')
        return value + joined if tag == _JOIN_AFTER else joined + value
    raise _bad('it uses a step other than "join before", "join after" and SHA-256.')


def _read_from(r, value, depth, found):
    """Everything that follows from a value. Each thing but the last is marked
    as one of several. The JavaScript library reads this by calling itself;
    here the same order of reading is kept with a list of the values whose
    several things are not yet all read, so that a deep proof cannot
    exhaust Python's own limit on calls."""
    waiting = []
    while True:
        if depth > _MAX_DEPTH:
            raise _bad('its steps go deeper than the format allows.')
        tag = r.byte()
        if tag == _FORK:
            # One of several: after it, the next thing that follows from this value is read.
            waiting.append((value, depth))
            tag = r.byte()
        following = _read_item(r, tag, value, found)
        if following is not None:
            value, depth = following, depth + 1
            continue
        if not waiting:
            return
        value, depth = waiting.pop()


def block_fingerprint(header):
    """The fingerprint of a block, as it is written everywhere: SHA-256 taken
    twice over the header, the bytes in reverse order, in hex (64 characters)."""
    return sha256(sha256(bytes(header)))[::-1].hex()


def block_stamp_item(proof, header):
    """Put a proof and the header of its block in the form they have beside a
    seal or a cancellation, in the list "stamps".

    proof: the proof file, complete: it must lead to a block. header: the
    80-byte header of that block. Returns {"block", "proof"}.
    """
    if not isinstance(proof, (bytes, bytearray)) or len(proof) == 0 or len(proof) > MAX_PROOF_BYTES:
        raise _bad('it must be at most 12,288 bytes.')
    if not isinstance(header, (bytes, bytearray)) or len(header) != BLOCK_HEADER_BYTES:
        raise _bad('the block header that comes with it must be 80 bytes.')
    return {'block': to_base64url(header), 'proof': to_base64url(proof)}


def check_block_stamp(proof, header, fingerprint_bytes, trusted=None):
    """Check one block time-stamp.

    proof: the proof file. header: the 80-byte header of the block the proof
    leads to. fingerprint_bytes: the 32 bytes that must have been stamped.
    trusted: the fingerprints (64 hex characters) of the blocks the checker
    trusts to be part of the chain.

    Returns {"kind", "state", "when", "time", "earliest", "authority",
    "height"}. "valid": the proof leads to a block the checker named.
    "untrusted": it leads to the block that comes with it, which the checker
    did not name; never treat this as a time. "when" is the time the block
    states. A block's time is only right to within about two hours, so there
    are two times in milliseconds. "time" is when the record existed by: the
    stated time and two hours. "earliest" is the earliest the proof could
    have been made: the stated time less two hours. "authority" is the
    block's fingerprint. "height" is the block's number as the proof states
    it; nothing checks it.

    Raises a Refusal: "stamp-bad-data", "stamp-wrong-data" or "stamp-invalid".
    """
    if not isinstance(proof, (bytes, bytearray)) or len(proof) > MAX_PROOF_BYTES:
        raise _bad('it must be at most 12,288 bytes.')
    if not isinstance(header, (bytes, bytearray)) or len(header) != BLOCK_HEADER_BYTES:
        raise _bad('the block header that comes with it must be 80 bytes.')
    proof = bytes(proof)
    header = bytes(header)
    r = _Reader(proof)
    if r.take(len(_MAGIC)) != _MAGIC:
        raise _bad('it does not begin as a proof file does.')
    if r.byte() != 1:
        raise _bad('it is not version 1 of the format.')
    if r.byte() != _SHA256:
        raise _bad('its first fingerprint is not SHA-256.')
    stamped = r.take(32)
    found = []
    _read_from(r, stamped, 0, found)
    if not r.done():
        raise _bad('there are bytes after its end.')

    if not isinstance(fingerprint_bytes, (bytes, bytearray)) or stamped != bytes(fingerprint_bytes):
        raise Refusal('stamp-wrong-data', 'A block time-stamp was made for something other than this record.')
    # The Merkle root is bytes 36 to 67 of a block header, and the time bytes 68 to 71, lowest first.
    root = header[36:68]
    match = next((f for f in found if f['root'] == root), None)
    if match is None:
        raise Refusal('stamp-invalid', 'A block time-stamp does not lead to the block that comes with it.')
    stated = (header[68] + header[69] * 2**8 + header[70] * 2**16 + header[71] * 2**24) * 1000
    fingerprint = block_fingerprint(header)
    named = isinstance(trusted, list) and any(isinstance(t, str) and t.lower() == fingerprint for t in trusted)
    return {
        'kind': 'block',
        'state': 'valid' if named else 'untrusted',
        'when': format_time(stated),
        'time': stated + BLOCK_TIME_ALLOWANCE_MS,
        'earliest': stated - BLOCK_TIME_ALLOWANCE_MS,
        'authority': fingerprint,
        'height': match['height'],
    }
