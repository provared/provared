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


def parse(text):
    """JSON.parse: the value, with numbers as JavaScript reads them.

    Raises ValueError where JSON.parse throws.
    """
    if not isinstance(text, str):
        raise _NotJson('not text')
    try:
        return json.loads(text, parse_int=_number_int, parse_constant=_no_constant)
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
                return ''.join(out), i + 1
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
            value = _number_int(t) if re.fullmatch(r'-?[0-9]+', t) else float(t)
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
    return len(text) + sum(1 for c in text if ord(c) > 0xFFFF)


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


def number_text(value):
    """String(value) for a whole number."""
    if isinstance(value, float):
        return str(int(value))
    return str(value)
