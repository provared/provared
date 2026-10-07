# Bytes, base64url, the canonical form of JSON, fingerprints and times.
#
# Nothing here is specific to a kind of record. Each function does exactly
# what its namesake in the JavaScript library's src/encoding.js does.

import hashlib
import os
import re
import time as _time

from . import _js


class Refusal(Exception):
    """A refusal: a named reason why a record does not check. A failed check is
    a normal answer, not a crash, so callers catch this and report its code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def problem_from(e):
    """Turn anything raised while checking into a problem to report. A Refusal
    keeps its code. Anything else means the checker itself met something it
    did not expect: that is reported as "check-failed" and is never a pass."""
    if isinstance(e, Refusal):
        return {'code': e.code, 'message': e.message}
    return {'code': 'check-failed', 'message': 'The checker met something it did not expect here. This is treated as not intact.'}


MAX_NUMBER = _js.MAX_SAFE_INTEGER
"""The largest whole number the format allows (2^53 - 1)."""

MAX_DEPTH = 8
"""How deep the content of a record or a line of a book may nest."""


def utf8(text):
    """TextEncoder.encode: a surrogate without its other half becomes U+FFFD."""
    try:
        return text.encode('utf-8')
    except UnicodeEncodeError:
        return text.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'replace').encode('utf-8')


def from_utf8(data, code='not-json'):
    """Strict UTF-8 decoding. A byte order mark is kept in the text."""
    try:
        return bytes(data).decode('utf-8', 'strict')
    except UnicodeDecodeError:
        raise Refusal(code, 'The bytes are not valid UTF-8 text.') from None


def sha256(data):
    """SHA-256 (FIPS 180-4)."""
    return hashlib.sha256(bytes(data)).digest()


# --- base64url (RFC 4648 section 5, no padding; RFC 7515 section 2) ---

_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
_LOOKUP = {c: i for i, c in enumerate(_ALPHABET)}


def to_base64url(data):
    data = bytes(data)
    out = []
    i = 0
    n = len(data)
    while i + 2 < n:
        v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
        out.append(_ALPHABET[(v >> 18) & 63] + _ALPHABET[(v >> 12) & 63] + _ALPHABET[(v >> 6) & 63] + _ALPHABET[v & 63])
        i += 3
    if i + 1 == n:
        v = data[i] << 16
        out.append(_ALPHABET[(v >> 18) & 63] + _ALPHABET[(v >> 12) & 63])
    elif i + 2 == n:
        v = (data[i] << 16) | (data[i + 1] << 8)
        out.append(_ALPHABET[(v >> 18) & 63] + _ALPHABET[(v >> 12) & 63] + _ALPHABET[(v >> 6) & 63])
    return ''.join(out)


def from_base64url(text):
    """Strict decoding: refuses any character outside the alphabet, padding, an
    impossible length, and stray bits in the last character. So one value has
    exactly one text form."""
    if not isinstance(text, str):
        raise Refusal('bad-base64url', 'A base64url value must be text.')
    if _js.utf16_length(text) % 4 == 1:
        raise Refusal('bad-base64url', 'A base64url value has an impossible length.')
    out = bytearray()
    acc = 0
    bits = 0
    for c in text:
        v = _LOOKUP.get(c, -1)
        if v < 0:
            raise Refusal('bad-base64url', 'A base64url value holds a character that is not allowed.')
        acc = (acc << 6) | v
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
            acc &= (1 << bits) - 1
    if acc != 0:
        raise Refusal('bad-base64url', 'A base64url value has stray bits in its last character.')
    return bytes(out)


# --- the canonical form (RFC 8785, narrowed as the format description says) ---


def _well_formed(text):
    # Python joins a pair of surrogates written as escapes into one character,
    # so any surrogate left is one without its other half.
    chars = text
    i = 0
    n = len(chars)
    while i < n:
        o = ord(chars[i])
        if 0xD800 <= o <= 0xDBFF:
            if i + 1 < n and 0xDC00 <= ord(chars[i + 1]) <= 0xDFFF:
                i += 2
                continue
            return False
        if 0xDC00 <= o <= 0xDFFF:
            return False
        i += 1
    return True


def canonical_json(value, depth=0):
    """Write a value in the canonical form: RFC 8785, narrowed to objects, lists,
    strings and whole numbers from 0 to 2^53 - 1. For those types RFC 8785 is
    exactly: members sorted by name (by UTF-16 code unit), strings as
    JSON.stringify writes them, no spaces."""
    if isinstance(value, str):
        if not _well_formed(value):
            raise Refusal('payload-not-canonical', 'A string is not well-formed Unicode.')
        return _js.string(value)
    if _js.is_number(value):
        if not _js.is_safe_integer(value) or value < 0 or (isinstance(value, float) and value == 0 and str(value).startswith('-')):
            raise Refusal('payload-not-canonical', 'A number must be a whole number from 0 to 9,007,199,254,740,991.')
        return _js.number_text(value)
    if not isinstance(value, (dict, list)):
        raise Refusal('payload-not-canonical', 'Only objects, lists, strings and whole numbers are allowed.')
    if depth >= MAX_DEPTH:
        raise Refusal('payload-not-canonical', 'The content nests too deeply.')
    if isinstance(value, list):
        return '[' + ','.join(canonical_json(item, depth + 1) for item in value) + ']'
    for name in value:
        if not isinstance(name, str):
            raise Refusal('payload-not-canonical', 'Only objects, lists, strings and whole numbers are allowed.')
    names = _js.sort_strings(value.keys())
    return '{' + ','.join(canonical_json(n, depth + 1) + ':' + canonical_json(value[n], depth + 1) for n in names) + '}'


def parse_canonical(text, code='payload-not-canonical'):
    """Read JSON text that must already be in the canonical form. The text is
    parsed, written again canonically, and refused if the two differ. This
    refuses a repeated member name, stray spaces and unusual number forms."""
    try:
        value = _js.parse(text)
    except ValueError:
        raise Refusal(code if code == 'payload-not-canonical' else 'not-json', 'The text is not JSON.') from None
    try:
        again = canonical_json(value)
    except Refusal as e:
        raise Refusal(code, e.message) from None
    except RecursionError:
        raise Refusal(code, 'The content nests too deeply.') from None
    if again != text:
        raise Refusal(code, 'The JSON is not in the canonical form (a repeated name, stray spaces, or members out of order).')
    return value


def count_characters(text):
    """How many characters a text holds, counted as Unicode code points, so that
    every implementation counts the same way."""
    # The second half of a pair does not count again; Python already holds a
    # pair as one character, and a lone second half is not counted, as in JavaScript.
    return sum(1 for c in text if not (0xDC00 <= ord(c) <= 0xDFFF))


def fingerprint(content_bytes):
    """The fingerprint of a record: SHA-256 of its content bytes, in base64url."""
    return to_base64url(sha256(content_bytes))


# --- times (RFC 3339, UTC, to the second) ---

_TIME = re.compile(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z')


def _days_from_civil(y, m, d):
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(z):
    z += 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return y + (m <= 2), m, d


def _days_in_month(y, m):
    if m == 2:
        return 29 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28
    return 30 if m in (4, 6, 9, 11) else 31


def parse_time(text):
    """Milliseconds since 1970, or None if the text is not a time in the one accepted form."""
    if not isinstance(text, str):
        return None
    m = _TIME.fullmatch(text)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups())
    # Refuses dates that do not exist, such as 30 February.
    if not (1 <= mo <= 12 and 1 <= d <= _days_in_month(y, mo) and h <= 23 and mi <= 59 and s <= 59):
        return None
    return ((_days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60000 + s * 1000


MAX_TIME_MS = 8.64e15


def format_time(when):
    """A time in milliseconds since 1970, written as YYYY-MM-DDTHH:MM:SSZ."""
    if not _js.is_number(when) or when != when or abs(when) > MAX_TIME_MS:
        raise ValueError('Invalid time value')
    # new Date() cuts a fraction of a millisecond off towards zero.
    ms = int(when)
    days, rest = divmod(ms, 86400000)
    y, mo, d = _civil_from_days(days)
    secs = rest // 1000
    h, secs = divmod(secs, 3600)
    mi, s = divmod(secs, 60)
    year = '%04d' % y if 0 <= y <= 9999 else ('+' if y > 0 else '-') + '%06d' % abs(y)
    return '%s-%02d-%02dT%02d:%02d:%02dZ' % (year, mo, d, h, mi, s)


def now_ms():
    """Date.now()"""
    return _time.time_ns() // 1_000_000


def random_id():
    """16 random bytes in base64url: the unique number of a record."""
    return to_base64url(os.urandom(16))
