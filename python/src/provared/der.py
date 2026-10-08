# A small, strict reader for DER, the byte layout that time-stamps and
# certificates use (ITU-T X.690). It reads; it never writes. Anything not in
# the one form DER allows is refused.

import math
import re

from .encoding import Refusal, _days_from_civil


def bad_stamp(why):
    return Refusal('stamp-bad-data', f'A time-stamp is not laid out as its standard sets out: {why}')


class TAG:
    """The tags this reader meets."""

    BOOLEAN = 0x01
    INTEGER = 0x02
    BIT_STRING = 0x03
    OCTET_STRING = 0x04
    NULL = 0x05
    OID = 0x06
    UTC_TIME = 0x17
    GENERALIZED_TIME = 0x18
    SEQUENCE = 0x30
    SET = 0x31
    CONTEXT_0 = 0xA0
    CONTEXT_1 = 0xA1
    CONTEXT_3 = 0xA3


class Element:
    """One element: "from_" is its first byte, "start" and "end" bound its content."""

    __slots__ = ('tag', 'from_', 'start', 'end')

    def __init__(self, tag, from_, start, end):
        self.tag = tag
        self.from_ = from_
        self.start = start
        self.end = end

    def as_dict(self):
        """The element as JavaScript gives it: {tag, from, start, end}."""
        return {'tag': self.tag, 'from': self.from_, 'start': self.start, 'end': self.end}


def read_element(data, at, end=None):
    """Read the element that begins at "at". It must lie before "end"."""
    if end is None:
        end = len(data)
    if at + 2 > end:
        raise bad_stamp('it is cut short.')
    tag = data[at]
    if (tag & 0x1F) == 0x1F:
        raise bad_stamp('it holds a tag of a kind that is not used here.')
    length = data[at + 1]
    start = at + 2
    if length & 0x80:
        count = length & 0x7F
        # Never the indefinite form, and never more than four bytes of length.
        if count == 0 or count > 4:
            raise bad_stamp('it holds a length in a form that is not allowed.')
        if start + count > end:
            raise bad_stamp('it is cut short.')
        length = 0
        for i in range(count):
            length = length * 256 + data[start + i]
        if data[start] == 0 or length < 128:
            raise bad_stamp('it holds a length that is not in its shortest form.')
        start += count
    if length > end - start:
        raise bad_stamp('a part is longer than what holds it.')
    return Element(tag, at, start, start + length)


def children(data, parent, most=32):
    """The elements inside a constructed element, in order. More than "most" is refused."""
    out = []
    at = parent.start
    while at < parent.end:
        if len(out) >= most:
            raise bad_stamp('a part holds too many items.')
        child = read_element(data, at, parent.end)
        out.append(child)
        at = child.end
    return out


def item(elements, i):
    """elements[i], or None where there is no such item, as JavaScript gives undefined."""
    return elements[i] if 0 <= i < len(elements) else None


def expect(element, tag, what):
    """Confirm an element's tag, and hand the element back."""
    if element is None or element.tag != tag:
        raise bad_stamp(f'{what} is missing or of the wrong kind.')
    return element


def content_of(data, element):
    """The content bytes of an element."""
    return bytes(data[element.start:element.end])


def whole_of(data, element):
    """The whole element, tag and length included."""
    return bytes(data[element.from_:element.end])


def hex_of(data, element):
    """The content of an element as lower-case hexadecimal: how object identifiers are compared here."""
    return bytes(data[element.start:element.end]).hex()


_UTC_TIME = re.compile(r'([0-9][0-9])([0-9][0-9])([0-9][0-9])([0-9][0-9])([0-9][0-9])([0-9][0-9])Z')
_GENERALIZED_TIME = re.compile(r'([0-9]{4})([0-9][0-9])([0-9][0-9])([0-9][0-9])([0-9][0-9])([0-9][0-9])(?:\.([0-9]{1,9}))?Z')


def _days_in_month(y, m):
    if m == 2:
        return 29 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28
    return 30 if m in (4, 6, 9, 11) else 31


def time_of(data, element):
    """A time, from the two forms DER allows: "YYMMDDHHMMSSZ" (UTCTime) and
    "YYYYMMDDHHMMSS[.f]Z" (GeneralizedTime). Returns milliseconds."""
    text = ''.join(chr(b) for b in data[element.start:element.end])
    groups = None
    if element.tag == TAG.UTC_TIME:
        m = _UTC_TIME.fullmatch(text)
        if m:
            groups = list(m.groups()) + [None]
            groups[0] = ('20' if int(groups[0]) < 50 else '19') + groups[0]
    elif element.tag == TAG.GENERALIZED_TIME:
        m = _GENERALIZED_TIME.fullmatch(text)
        # DER allows no trailing zero in the fraction.
        if m and not (m.group(7) and m.group(7).endswith('0')):
            groups = list(m.groups())
    if groups is None:
        raise bad_stamp('a time is not written in the form DER allows.')
    y, mo, d, h, mi, s = (int(g) for g in groups[:6])
    fraction = groups[6]
    # JavaScript's Date.UTC reads a year from 0 to 99 as 1900 to 1999, so
    # such a year never names the moment it says, and is refused there.
    if y <= 99 or not (1 <= mo <= 12) or not (1 <= d <= _days_in_month(y, mo)) or h > 23 or mi > 59 or s > 59:
        raise bad_stamp('a time names a moment that does not exist.')
    ms = ((_days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60000 + s * 1000
    if fraction:
        ms += math.floor(float('0.' + fraction) * 1000)
    return ms


def ecdsa_to_raw(der, size):
    """An ECDSA signature from its DER form (two whole numbers) to the two
    numbers side by side, each of "size" bytes, as Web Crypto wants them.
    size: 32 for P-256, 48 for P-384."""
    der = bytes(der)
    outer = expect(read_element(der, 0), TAG.SEQUENCE, 'the signature')
    if outer.end != len(der):
        raise bad_stamp('a signature has bytes left over.')
    parts = children(der, outer, 2)
    if len(parts) != 2:
        raise bad_stamp('a signature does not hold two numbers.')
    out = bytearray(size * 2)
    for i, part in enumerate(parts):
        expect(part, TAG.INTEGER, 'a number of the signature')
        digits = content_of(der, part)
        if len(digits) == 0 or digits[0] & 0x80:
            raise bad_stamp('a signature holds a number that is not positive.')
        if len(digits) > 1 and digits[0] == 0 and not (digits[1] & 0x80):
            raise bad_stamp('a signature holds a number not in its shortest form.')
        if digits[0] == 0:
            digits = digits[1:]
        if len(digits) > size:
            raise bad_stamp('a signature holds a number that is too large.')
        at = i * size + (size - len(digits))
        out[at:at + len(digits)] = digits
    return bytes(out)


def validate_der(data, element):
    """Walk a whole element and everything inside it, and refuse anything that
    is not strict DER: a constructed part whose items do not fill it exactly,
    a whole number or an object identifier that is not in its shortest form,
    a truth value that is not written in the one way DER allows. Parts this
    checker does not otherwise read are still read here, so that two checkers
    cannot disagree about whether a time-stamp is well formed."""
    budget = [4000]

    def walk(e, depth):
        budget[0] -= 1
        if budget[0] < 0 or depth > 24:
            raise bad_stamp('it holds too many parts, or parts nested too deeply.')
        length = e.end - e.start
        if e.tag & 0x20:
            at = e.start
            while at < e.end:
                child = read_element(data, at, e.end)
                walk(child, depth + 1)
                at = child.end
            return
        if e.tag == TAG.INTEGER:
            if length == 0:
                raise bad_stamp('a whole number is empty.')
            if length > 1:
                first = data[e.start]
                second = data[e.start + 1]
                if (first == 0x00 and not (second & 0x80)) or (first == 0xFF and second & 0x80):
                    raise bad_stamp('a whole number is not in its shortest form.')
        elif e.tag == TAG.OID:
            if length == 0 or data[e.end - 1] & 0x80:
                raise bad_stamp('an object identifier is empty or cut short.')
            for i in range(e.start, e.end):
                if data[i] == 0x80 and (i == e.start or not (data[i - 1] & 0x80)):
                    raise bad_stamp('an object identifier is not in its shortest form.')
        elif e.tag == TAG.BOOLEAN:
            if length != 1 or data[e.start] not in (0x00, 0xFF):
                raise bad_stamp('a truth value is not written as DER allows.')
        elif e.tag == TAG.NULL:
            if length != 0:
                raise bad_stamp('an empty value is not empty.')
        elif e.tag == TAG.BIT_STRING:
            if length == 0 or data[e.start] > 7:
                raise bad_stamp('a string of bits is not written as DER allows.')

    walk(element, 0)
