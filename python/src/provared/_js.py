# How JavaScript reads and writes JSON and text, copied exactly, so that
# this library gives the same answer as the JavaScript one for every input.
#
# JavaScript strings are counted, sorted and compared in UTF-16 code units,
# and JSON.parse reads numbers as 64-bit floating-point values. Where Python
# does otherwise, the functions here do as JavaScript does.

import json
import re

MAX_SAFE_INTEGER = 2**53 - 1


class _NotJson(ValueError):
    pass


def _no_constant(name):
    # JSON.parse refuses NaN, Infinity and -Infinity, which Python's reader accepts.
    raise _NotJson(name)


def _number_int(text):
    # JSON.parse gives -0 for "-0", and a floating-point value for a long
    # number. Python gives 0 and an exact whole number.
    if text == '-0':
        return -0.0
    if len(text) > 16:
        return float(text)
    return int(text)


def _number_float(text):
    """A number written with a point or an exponent. JavaScript has one kind
    of number, so one that is whole (and no larger than 2^53 - 1) is held
    as a whole number, as it is written back in JavaScript. -0 stays -0."""
    value = float(text)
    if value.is_integer() and abs(value) <= MAX_SAFE_INTEGER and not (value == 0 and text.lstrip().startswith('-')):
        return int(value)
    return value


def parse(text):
    """JSON.parse: the value, with numbers as JavaScript reads them.

    Raises ValueError where JSON.parse throws.
    """
    if not isinstance(text, str):
        raise _NotJson('not text')
    try:
        return json.loads(text, parse_int=_number_int, parse_float=_number_float, parse_constant=_no_constant)
    except RecursionError:
        # Python's reader gives up on deep nesting, where JSON.parse does not.
        return _parse_deep(text)
    except (ValueError, OverflowError) as e:
        raise _NotJson(str(e)) from None


_WS = ' \t\n\r'
_NUMBER = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')
_ESCAPES = {'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}
_HEX = re.compile(r'[0-9a-fA-F]{4}')


def _parse_deep(text):
    """JSON.parse without recursion, for deeply nested text."""
    n = len(text)
    i = 0

    def skip(i):
        while i < n and text[i] in _WS:
            i += 1
        return i

    def read_string(i):
        # text[i] is the opening quotation mark.
        i += 1
        out = []
        start = i
        while True:
            if i >= n:
                raise _NotJson('unterminated string')
            c = text[i]
            if c == '"':
                out.append(text[start:i])
                return ''.join(out).encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass'), i + 1
            if c == '\\':
                out.append(text[start:i])
                if i + 1 >= n:
                    raise _NotJson('bad escape')
                e = text[i + 1]
                if e == 'u':
                    h = text[i + 2:i + 6]
                    if not _HEX.fullmatch(h):
                        raise _NotJson('bad escape')
                    out.append(chr(int(h, 16)))
                    i += 6
                elif e in _ESCAPES:
                    out.append(_ESCAPES[e])
                    i += 2
                else:
                    raise _NotJson('bad escape')
                start = i
                continue
            if ord(c) < 0x20:
                raise _NotJson('control character in string')
            i += 1

    # A stack of containers being filled: [container, pending member name].
    stack = []
    root = None
    have_root = False
    i = skip(i)
    while True:
        if i >= n:
            raise _NotJson('unexpected end')
        c = text[i]
        # Read one value, or open a container.
        if c == '{' or c == '[':
            container = {} if c == '{' else []
            i = skip(i + 1)
            if i < n and text[i] == ('}' if c == '{' else ']'):
                value = container
                i += 1
            else:
                if c == '{':
                    if i >= n or text[i] != '"':
                        raise _NotJson('expected a name')
                    name, i = read_string(i)
                    i = skip(i)
                    if i >= n or text[i] != ':':
                        raise _NotJson('expected a colon')
                    i = skip(i + 1)
                    stack.append([container, name])
                else:
                    stack.append([container, None])
                continue
        elif c == '"':
            value, i = read_string(i)
        elif c in '-0123456789':
            m = _NUMBER.match(text, i)
            if not m:
                raise _NotJson('bad number')
            t = m.group(0)
            value = _number_int(t) if re.fullmatch(r'-?[0-9]+', t) else _number_float(t)
            i = m.end()
        elif text.startswith('true', i):
            value, i = True, i + 4
        elif text.startswith('false', i):
            value, i = False, i + 5
        elif text.startswith('null', i):
            value, i = None, i + 4
        else:
            raise _NotJson('unexpected character')
        # Put the value in place, and close what is complete.
        while True:
            if not stack:
                root, have_root = value, True
                break
            container, name = stack[-1]
            if isinstance(container, dict):
                container[name] = value
            else:
                container.append(value)
            i = skip(i)
            if i < n and text[i] == ',':
                i = skip(i + 1)
                if isinstance(container, dict):
                    if i >= n or text[i] != '"':
                        raise _NotJson('expected a name')
                    name, i = read_string(i)
                    i = skip(i)
                    if i >= n or text[i] != ':':
                        raise _NotJson('expected a colon')
                    i = skip(i + 1)
                    stack[-1][1] = name
                break
            close = '}' if isinstance(container, dict) else ']'
            if i < n and text[i] == close:
                stack.pop()
                value = container
                i += 1
                continue
            raise _NotJson('expected a comma or the end of a container')
        if have_root:
            break
        i = skip(i)
    if skip(i) != n:
        raise _NotJson('text after the value')
    return root


_STRING_ESCAPES = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def string(text):
    """JSON.stringify of a string."""
    out = ['"']
    for c in text:
        o = ord(c)
        if c in _STRING_ESCAPES:
            out.append(_STRING_ESCAPES[c])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            out.append('\\u%04x' % o)
        else:
            out.append(c)
    out.append('"')
    return ''.join(out)


def utf16_key(text):
    """A key that sorts strings as JavaScript's default sort does: by UTF-16 code unit."""
    return text.encode('utf-16-be', 'surrogatepass')


def utf16_length(text):
    """A string's "length" in JavaScript: its UTF-16 code units."""
    if text.isascii():
        return len(text)
    return len(text.encode('utf-16-le', 'surrogatepass')) // 2


def sort_strings(names):
    return sorted(names, key=utf16_key)


_INDEX = re.compile(r'0|[1-9][0-9]*')


def keys(obj):
    """Object.keys of an object read from JSON: names that are list indexes
    (0 to 2**32 - 2) first, in number order, then the others as written."""
    indexes = []
    others = []
    for k in obj:
        if _INDEX.fullmatch(k) and int(k) <= 4294967294:
            indexes.append(k)
        else:
            others.append(k)
    if not indexes:
        return others
    indexes.sort(key=int)
    return indexes + others


def is_object(value):
    """value !== null && typeof value === 'object' && !Array.isArray(value)"""
    return isinstance(value, dict)


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_safe_integer(value):
    """Number.isSafeInteger"""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER
    if isinstance(value, float):
        return value == value and value not in (float('inf'), float('-inf')) and value.is_integer() and abs(value) <= MAX_SAFE_INTEGER
    return False


def whole(value):
    """A number that JavaScript holds as a whole number, as an int: so 2.0 is 2.
    Anything else is given back as it is."""
    if isinstance(value, float) and value.is_integer() and abs(value) <= MAX_SAFE_INTEGER:
        return int(value)
    return value


def in_key_order(obj):
    """An object with its members in the order Object.keys gives them."""
    return {k: obj[k] for k in keys(obj)}


def truthy(value):
    """Whether JavaScript counts a value as true: everything but undefined,
    null, false, 0, NaN and the empty text. An empty list or object counts."""
    if value is None or value is False:
        return False
    if is_number(value):
        return value == value and value != 0
    if isinstance(value, str):
        return value != ''
    return True


def strict_equal(a, b):
    """a === b for values read from JSON: true and 1 are not the same, nor are
    a number and a text."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if is_number(a) and is_number(b):
        return a == b
    if a is None or b is None:
        return a is b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b


def includes(items, value):
    """Array.prototype.includes, which compares as === does (and finds NaN)."""
    if isinstance(value, float) and value != value:
        return any(isinstance(x, float) and x != x for x in items)
    return any(strict_equal(x, value) for x in items)


class IdentityMap:
    """A JavaScript Map whose keys are objects: found by identity, not by value."""

    __slots__ = ('_items',)

    def __init__(self, items=None):
        self._items = dict(items._items) if isinstance(items, IdentityMap) else {}

    def get(self, key, default=None):
        found = self._items.get(id(key))
        return default if found is None else found[1]

    def set(self, key, value):
        self._items[id(key)] = (key, value)

    def has(self, key):
        return id(key) in self._items

    def values(self):
        return [v for _, v in self._items.values()]

    def __len__(self):
        return len(self._items)


def number_text(value):
    """String(value) for a whole number."""
    if isinstance(value, float):
        return str(int(value))
    return str(value)


def number_value(value):
    """The number JavaScript would hold for a Python number: a float, or an
    int that a float holds exactly. A whole number beyond 2^53 - 1 becomes
    the nearest float, as JSON.parse would read it. Raises OverflowError for
    a whole number too large for a float."""
    if isinstance(value, int) and not isinstance(value, bool):
        if -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            return value
        return float(value)
    return value


def number_string(value):
    """Number.prototype.toString() in base 10, which JSON.stringify also
    uses for a finite number: the fewest digits that read back as the same
    number, written as ECMAScript sets out (section 6.1.6.1.20). So 1e21 is
    "1e+21", 1.5e-7 is "1.5e-7", 1e-6 is "0.000001" and 0.1 + 0.2 is
    "0.30000000000000004". Raises OverflowError for a whole number too large
    for a float."""
    value = number_value(value)
    if isinstance(value, int):
        return str(value)
    if value != value:
        return 'NaN'
    if value in (float('inf'), float('-inf')):
        return 'Infinity' if value > 0 else '-Infinity'
    if value == 0:
        # Both 0 and -0 are written "0".
        return '0'
    sign = '-' if value < 0 else ''
    # Python's repr gives the same fewest digits, closest to the value.
    mantissa, _, exponent = repr(abs(value)).partition('e')
    whole, _, fraction = mantissa.partition('.')
    digits = whole + fraction
    # The value is 0.digits times 10 to the power "point".
    point = len(whole) + (int(exponent) if exponent else 0)
    stripped = digits.lstrip('0')
    point -= len(digits) - len(stripped)
    digits = stripped.rstrip('0')
    k = len(digits)
    n = point
    if k <= n <= 21:
        out = digits + '0' * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + '.' + digits[n:]
    elif -6 < n <= 0:
        out = '0.' + '0' * (-n) + digits
    else:
        e = n - 1
        mark = '+' if e >= 0 else '-'
        out = (digits if k == 1 else digits[0] + '.' + digits[1:]) + 'e' + mark + str(abs(e))
    return sign + out


def stringify(value):
    """JSON.stringify for plain data (objects, lists, text, numbers, true,
    false and null): NaN and the infinities are written null, -0 as 0, and
    members in the order Object.keys gives them."""
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, str):
        return string(value)
    if is_number(value):
        if isinstance(value, float) and (value != value or value in (float('inf'), float('-inf'))):
            return 'null'
        return number_string(value)
    if isinstance(value, list):
        return '[' + ','.join(stringify(v) for v in value) + ']'
    if isinstance(value, dict):
        return '{' + ','.join(string(k) + ':' + stringify(value[k]) for k in keys(value)) + '}'
    raise TypeError('not plain data')
