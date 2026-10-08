# A chain of block headers, checked on this device: the means to know,
# without asking anyone, that a block which a block time-stamp leads to is
# part of the Bitcoin blockchain.
#
# Nothing here makes a request. The headers come from a file the person
# has; the command provared-headers of the JavaScript library fetches them
# from Bitcoin nodes the person names, and nothing else in this library
# does.
#
# Each header is checked against the one before it, by the rules every
# Bitcoin node applies to headers: it names the block before it; its
# double SHA-256 meets the target written in it; that target follows the
# difficulty rule (unchanged within a run of 2,016 blocks, recomputed at
# the start of each run from the time the run before it took); its time is
# later than the middle of the eleven before it, and not more than two
# hours ahead of this device's clock. The first header must be the
# chain's own first block, and the chain must hold the blocks listed
# below at their places. Those known blocks are what stops a chain that
# branches off early and keeps its difficulty low: such a chain would have
# to hold each of them, which no one can make without the real chain's
# work.

import hashlib
import math
import re
import struct
import types

from .encoding import Refusal, format_time, now_ms

HEADER_BYTES = 80
"""The bytes of one block header."""

MIN_BLOCKS_AFTER = 6
"""A block counts as part of the chain only with at least this many blocks after it."""

MAX_HEADERS = 2_000_000
"""The most headers a chain file may hold: room for the chain to about the year 2045."""


def _double_sha256(data):
    return hashlib.sha256(hashlib.sha256(bytes(data)).digest()).digest()


def _written(hash_bytes):
    """A block's fingerprint as it is written everywhere: the hash's bytes in reverse order, in hex."""
    return bytes(hash_bytes)[::-1].hex()


def _from_hex(text):
    # As the JavaScript library reads hex: pair by pair, a last single character left out.
    return bytes(int(text[i:i + 2], 16) for i in range(0, len(text) - 1, 2))


BITCOIN = types.MappingProxyType(
    {
        'first': '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c',
        # The easiest target a block may have.
        'limit': (1 << 224) - 1,
        # The difficulty is recomputed every 2,016 blocks, aiming at two weeks for each run.
        'interval': 2016,
        'timespan': 14 * 24 * 60 * 60,
        'retarget': True,
        # From these blocks on, a header's version must be at least this (the
        # upgrades of 2013 and 2015 that every node enforces).
        'versions': ((227931, 2), (363725, 3), (388381, 4)),
        # After the last known block, no target may be more than four times
        # easier than that block's. Every change of difficulty in the real chain
        # so far eased it by less than one and a half times; a branch made after
        # the last known block, with dates pushed forward to ease it at every
        # change, is held to work no less than a quarter of the real chain's then.
        'ease': 4,
        'known': (
            (100000, '000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506'),
            (200000, '000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf'),
            (300000, '000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254'),
            (400000, '000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f'),
            (500000, '00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04'),
            (600000, '00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91'),
            (700000, '0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959'),
            (800000, '00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054'),
            (900000, '000000000000000000010538edbfd2d5b809a33dd83f284aeea41c6d0d96968a'),
            (969696, '000000000000000000001e39df127cbab82a824ac43cfcdbf62e59f6a08b9f0b'),
        ),
    }
)
"""The rules of the Bitcoin chain that headers are checked by. The known
blocks were read on 5 October 2026 from the whole chain of headers, which
was checked by these rules from the first block on the author's computer,
and which a second node on another network agreed with.

Rules of another chain are given in the same form: "first" (the first
header in hex), "limit", "interval", "timespan", "retarget", "known" (a
list of [number, fingerprint]) and, where they apply, "versions" and
"ease"."""


def _invalid(message):
    return Refusal('headers-invalid', message)


# --- JavaScript's arithmetic on numbers, where the JavaScript library relies on it ---


def _uint32(value):
    """ToUint32: what JavaScript's bit operators make of a number."""
    if isinstance(value, float):
        if not math.isfinite(value):
            return 0
        value = math.trunc(value)
    return int(value) & 0xFFFFFFFF


def _int32(value):
    """ToInt32"""
    v = _uint32(value)
    return v - (1 << 32) if v & 0x80000000 else v


def _big(value):
    """BigInt(value) for a number: refused unless it is a whole number."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value) and value == math.floor(value):
        return int(value)
    raise ValueError('The number cannot be converted to a BigInt because it is not an integer')


def _big_divide(a, b):
    """Division of BigInts: the quotient, cut towards zero."""
    if b == 0:
        raise ZeroDivisionError('Division by zero')
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _number(value):
    """A value read as a JavaScript number, for adding and comparing."""
    return float(value) if not isinstance(value, float) else value


def _js_max(a, b):
    if a != a or b != b:
        return math.nan
    return a if a >= b else b


def _js_min(a, b):
    if a != a or b != b:
        return math.nan
    return a if a <= b else b


def _target_of(bits):
    """The target that a compact "bits" value stands for."""
    b = _uint32(bits)
    if b & 0x00800000:
        return -1  # a negative target: no hash meets it
    exponent = b >> 24
    mantissa = b & 0x007FFFFF
    return mantissa >> (8 * (3 - exponent)) if exponent <= 3 else mantissa << (8 * (exponent - 3))


def _compact_of(target):
    """The compact "bits" value of a target, as Bitcoin writes it."""
    written = format(target, 'x') if target >= 0 else '-' + format(-target, 'x')
    size = math.ceil(len(written) / 2)
    c = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    if _int32(c) & 0x00800000:
        c = _uint32(c) >> 8
        size += 1
    return (c | (size << 24)) & 0xFFFFFFFF


def next_bits(bits, first_time, last_time, rules=BITCOIN):
    """The "bits" at the start of a run: the target of the last block, scaled by
    how long the run took against how long it should, by at most four times
    either way, and never easier than the limit. Not part of the public
    interface.

    bits: the last block's bits. first_time: the time of the run's first
    block, in seconds. last_time: the time of the run's last block, in seconds.
    """
    timespan = rules['timespan']
    span = _js_min(_js_max(_number(last_time) - _number(first_time), timespan / 4), timespan * 4)
    if span != span or not math.isfinite(span):
        raise ValueError('The number cannot be converted to a BigInt because it is not an integer')
    target = _big_divide(_target_of(bits) * math.floor(span), _big(timespan))
    if target > rules['limit']:
        target = rules['limit']
    return _compact_of(target)


def _subarray(buffer, start, end):
    """TypedArray.prototype.subarray, with its rules for places before the start."""
    n = len(buffer)
    start = max(n + start, 0) if start < 0 else min(start, n)
    end = max(n + end, 0) if end < 0 else min(end, n)
    return bytes(buffer[start:max(start, end)])


class HeaderChain:
    """A chain of headers being read, one header at a time. Not part of the
    public interface: check_header_chain reads a whole file with it, and the
    command that fetches headers adds what it fetches."""

    def __init__(self, rules=BITCOIN, web_crypto=False):
        self.rules = rules
        self._web_crypto = web_crypto
        self._room = 1024
        self._headers = bytearray(self._room * HEADER_BYTES)
        self._hashes = bytearray(self._room * 32)
        self._count = 0
        self._known = {height: fingerprint for height, fingerprint in rules['known']}
        # The target of the bits last seen, as 32 bytes, most significant first,
        # so that a hash is compared with it byte by byte.
        self._target_bits = -1
        self._target_bytes = None
        # The last known block, and its target once the chain has reached it.
        known = rules['known']
        self._last_known = known[-1][0] if len(known) else -1
        self._floor = None
        versions = rules.get('versions')
        self._versions = [] if versions is None else versions

    # --- what is held ---

    def _view_uint32(self, offset):
        if offset < 0 or offset + 4 > len(self._headers):
            raise IndexError('Offset is outside the bounds of the DataView')
        return struct.unpack_from('<I', self._headers, offset)[0]

    def _time_at(self, h):
        return self._view_uint32(h * HEADER_BYTES + 68)

    def _bits_at(self, h):
        return self._view_uint32(h * HEADER_BYTES + 72)

    def _hash_at(self, h):
        return _subarray(self._hashes, h * 32, h * 32 + 32)

    def _meets(self, hash_bytes, bits):
        if bits != self._target_bits:
            target = _target_of(bits)
            self._target_bits = bits
            self._target_bytes = None if target <= 0 or target > self.rules['limit'] else _from_hex(format(target, 'x').rjust(64, '0'))
        if self._target_bytes is None:
            return False
        # The hash is a number written least significant byte first.
        for i in range(32):
            a = hash_bytes[31 - i]
            b = self._target_bytes[i]
            if a != b:
                return a < b
        return True

    def _grow(self):
        self._room *= 2
        more_headers = bytearray(self._room * HEADER_BYTES)
        more_headers[:self._count * HEADER_BYTES] = self._headers[:self._count * HEADER_BYTES]
        more_hashes = bytearray(self._room * 32)
        more_hashes[:self._count * 32] = self._hashes[:self._count * 32]
        self._headers = more_headers
        self._hashes = more_hashes

    @property
    def height(self):
        """The number of the latest block held; -1 before the first."""
        return self._count - 1

    def add(self, header, now):
        """Check one header as the next of the chain, and add it.

        header: 80 bytes. now: this device's clock, in milliseconds.
        """
        h = self._count
        rules = self.rules
        if not isinstance(header, (bytes, bytearray)) or len(header) != HEADER_BYTES:
            raise _invalid(f'Block {h}: a header must be 80 bytes.')
        if h >= MAX_HEADERS:
            raise _invalid(f'The chain holds more than {MAX_HEADERS} headers.')
        header = bytes(header)
        hash_bytes = _double_sha256(header)
        if h == 0:
            if header.hex() != rules['first']:
                raise _invalid("Block 0: this is not the chain's first block.")
        else:
            previous = self._hash_at(h - 1)
            for i in range(32):
                if header[4 + i] != previous[i]:
                    raise _invalid(f'Block {h}: it does not name the block before it.')
            bits = struct.unpack_from('<I', header, 72)[0]
            if rules['retarget'] and h % rules['interval'] == 0:
                expected = next_bits(self._bits_at(h - 1), self._time_at(h - rules['interval']), self._time_at(h - 1), rules)
            else:
                expected = self._bits_at(h - 1)
            if bits != expected:
                raise _invalid(f'Block {h}: its difficulty does not follow the rule.')
            if not self._meets(hash_bytes, bits):
                raise _invalid(f'Block {h}: its hash does not meet its target, so it does not carry the work it claims.')
            ease = rules.get('ease')
            if self._floor is not None and h > self._last_known and _target_of(bits) > self._floor * (4 if ease is None else ease):
                raise _invalid(f'Block {h}: its target is more than four times easier than that of block {self._last_known}, the last block known to be part of the chain.')
            version = struct.unpack_from('<i', header, 0)[0]
            for start, least in self._versions:
                if h >= start and version < least:
                    raise _invalid(f'Block {h}: its version is lower than every block from {start} on must have.')
            time = struct.unpack_from('<I', header, 68)[0]
            before = sorted(self._time_at(k) for k in range(max(0, h - 11), h))
            if time <= before[len(before) >> 1]:
                raise _invalid(f'Block {h}: its time is not later than the middle of the eleven blocks before it.')
            if time * 1000 > now + 7200 * 1000:
                raise _invalid(f"Block {h}: its time is more than two hours ahead of this device's clock.")
        if h in self._known and _written(hash_bytes) != self._known[h]:
            raise _invalid(f'Block {h}: it is not the block known to be at that place in the chain.')
        if h == self._last_known:
            self._floor = _target_of(struct.unpack_from('<I', header, 72)[0])
        if h >= self._room:
            self._grow()
        if (h + 1) * HEADER_BYTES > len(self._headers):
            # As in the JavaScript library, a chain that took on an empty one has no room to grow.
            raise IndexError('offset is out of bounds')
        self._headers[h * HEADER_BYTES:(h + 1) * HEADER_BYTES] = header
        self._hashes[h * 32:(h + 1) * 32] = hash_bytes
        self._count += 1

    def keep_to(self, height):
        """Keep the blocks up to and including this one, where another chain parts from this one near its end."""
        if height < 0 or height >= self._count:
            raise IndexError('no such block')
        self._count = height + 1
        if height < self._last_known:
            self._floor = None

    def copy(self):
        """A copy that shares nothing with this chain, to try another node's headers on."""
        other = HeaderChain(self.rules, self._web_crypto)
        size = max(self._count, 1)
        other._inside_set(bytearray(self._headers[:size * HEADER_BYTES]), bytearray(self._hashes[:size * 32]), self._count, self._floor)
        return other

    def adopt(self, other):
        """Take on what another chain holds: a branch that carries more work."""
        headers, hashes, count, floor = other._inside_get()
        self._headers = bytearray(headers)
        self._hashes = bytearray(hashes)
        self._room = len(self._headers) // HEADER_BYTES
        self._count = count
        self._floor = floor
        self._target_bits = -1

    def work_after(self, height):
        """The work of the blocks after this one, to the latest: the number of hashes their targets ask for, together."""
        work = 0
        for h in range(height + 1, self._count):
            target = _target_of(self._bits_at(h))
            if target > 0:
                work += (1 << 256) // (target + 1)
        return work

    def fingerprint_at(self, h):
        """The fingerprint of a block, 64 hex characters."""
        return _written(self._hash_at(h))

    def hash_at(self, h):
        """The hash of a block, as it is named inside the next header and in a request for headers."""
        return self._hash_at(h)

    def time_at(self, h):
        """The time a block states, in milliseconds."""
        return self._time_at(h) * 1000

    def height_of(self, fingerprint):
        """The number of the block with this fingerprint, or -1 where the chain does not hold it."""
        if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint):
            return -1
        wanted = bytes.fromhex(fingerprint)[::-1]
        for h in range(self._count - 1, -1, -1):
            if self._hashes[h * 32:h * 32 + 32] == wanted:
                return h
        return -1

    def bytes(self):
        """Every header held, one after another, as a chain file holds them."""
        return bytes(self._headers[:self._count * HEADER_BYTES])

    # What one chain hands another, and nothing else should reach.

    def _inside_get(self):
        return (bytes(self._headers[:self._count * HEADER_BYTES]), bytes(self._hashes[:self._count * 32]), self._count, self._floor)

    def _inside_set(self, headers, hashes, count, floor):
        self._headers = headers
        self._hashes = hashes
        self._room = max(1, len(headers) // HEADER_BYTES)
        self._count = count
        self._floor = floor
        self._target_bits = -1


def start_header_chain(rules=BITCOIN, web_crypto=False):
    """A chain of headers being read, one header at a time. Not part of the
    public interface. "web_crypto" is kept for the same interface as the
    JavaScript library, where it chooses another way to the same SHA-256."""
    return HeaderChain(rules, web_crypto)


def read_header_chain(data, now=None, rules=BITCOIN, partial=False, web_crypto=False):
    """Read a whole chain file into a chain being read. Not part of the public
    interface. Raises a Refusal "headers-invalid" at the first header that
    breaks a rule. A chain that ends before the last known block is refused,
    unless "partial": the command that fetches headers carries such a chain
    on; nothing may count a block in it."""
    if now is None:
        now = now_ms()
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0 or len(data) % HEADER_BYTES != 0:
        raise _invalid('A chain file holds whole headers of 80 bytes each, one after another, from the first block.')
    if len(data) / HEADER_BYTES > MAX_HEADERS:
        raise _invalid(f'The chain holds more than {MAX_HEADERS} headers.')
    data = bytes(data)
    chain = start_header_chain(rules, web_crypto)
    for at in range(0, len(data), HEADER_BYTES):
        chain.add(data[at:at + HEADER_BYTES], now)
    known = rules['known']
    last = known[-1] if len(known) else None
    if not partial and last and chain.height < last[0]:
        raise _invalid(f'The chain ends at block {chain.height}, before block {last[0]}, which is known to be part of it. Fetch more headers.')
    return chain


def check_header_chain(data, now=None):
    """Check a chain of Bitcoin block headers held in a file: every header, from
    the chain's first block, by the rules above. Nothing is asked of anyone.

    data: the headers, 80 bytes each, one after another, from the first
    block. now: this device's clock, in milliseconds; by default the
    device's own.

    Returns what answer_for gives: the number and fingerprint of the latest
    block, the time it states, and a way to find a block: its number, and
    how many blocks come after it in this chain.

    Raises a Refusal "headers-invalid", at the first header that breaks a rule.
    """
    return answer_for(read_header_chain(data, now=now))


def answer_for(chain):
    """What check_header_chain gives, for a chain that has been read: a dict
    with "height", "tip", "tipWhen" and "find", a function that gives
    {"height", "after"} for a block's fingerprint, or None. Not part of the
    public interface."""
    height = chain.height

    def find(fingerprint):
        at = chain.height_of(fingerprint)
        return None if at < 0 else {'height': at, 'after': height - at}

    return {'height': height, 'tip': chain.fingerprint_at(height), 'tipWhen': format_time(chain.time_at(height)), 'find': find}


def blocks_in_chain(result, chain):
    """The blocks a check's block time-stamps lead to that a chain of headers
    holds with at least MIN_BLOCKS_AFTER blocks after them: the blocks a
    person who checked that chain can name as trusted. Each block
    time-stamp the result shows is looked for, with what was found.

    result: what check_book or check_show returned. chain: what
    check_header_chain returned.

    Returns {"blocks": [fingerprint, ...], "found": [{"block", "stated",
    "height", "after", "counted"}, ...]}. "stated" is left out where the
    time-stamp states no number, as JSON leaves out a member that is
    undefined in JavaScript.
    """
    find = chain['find'] if isinstance(chain, dict) else chain.find
    stamps = []
    entries = result.get('entries')
    for e in [] if entries is None else entries:
        given = e.get('stamps')
        stamps.extend([] if given is None else given)
    held = result.get('held')
    for h in [] if held is None else held:
        given = h.get('stamps')
        stamps.extend([] if given is None else given)
    found = []
    seen = set()
    for s in stamps:
        if s is None:
            raise TypeError('a time-stamp that is null has no kind')
        if not isinstance(s, dict):
            continue
        authority = s.get('authority')
        if s.get('kind') != 'block' or not isinstance(authority, str) or authority in seen:
            continue
        seen.add(authority)
        at = find(authority)
        item = {'block': authority}
        if 'height' in s:
            item['stated'] = s['height']
        item['height'] = at['height'] if at is not None else None
        item['after'] = at['after'] if at is not None else None
        item['counted'] = at is not None and at['after'] >= MIN_BLOCKS_AFTER
        found.append(item)
    return {'blocks': [f['block'] for f in found if f['counted']], 'found': found}
