# The reserved names of the documents a stub names (format description,
# section 27), and the fingerprints they stand for.
#
# A stub's "details" names documents by their fingerprints. Most names are
# labels that whoever wrote the stub chose. Names that begin "provared."
# are reserved: each one on the list below says exactly which text its
# fingerprint is made from, so that an investigator who holds that text
# (the call's arguments, the HTTP request, the identifier a platform's own
# log shows for the call) can work the fingerprint out again and match
# the stub to it, without either side's help.

import base64
import re
import types

from .encoding import Refusal, _well_formed, fingerprint, sha256, utf8

RESERVED_DOCUMENT_PREFIX = 'provared.'
"""Every document name that begins with this is reserved for the list below."""

DOCUMENT_NAMES = types.MappingProxyType({
    'provared.arguments': "The call's arguments, written in the one form of RFC 8785.",
    'provared.http-request': 'The request, written as the signature base of RFC 9421, section 2.5, over "@method", "@target-uri" and, where there is a body, "content-digest" (RFC 9530, with SHA-256). No header is covered.',
    'provared.http-response': 'The answer, written as the signature base of RFC 9421, section 2.5, over "@status" and, where there is a body, "content-digest" (RFC 9530, with SHA-256). No header is covered.',
    'provared.trace-id': 'The trace-id of the W3C Trace Context "traceparent" header that the agent\'s side sent, which that standard writes as 32 lower-case hexadecimal characters. Its form is not checked.',
    'provared.request-id': "An identifier that the agent's side chose and sent with the call, exactly as sent.",
    'provared.event-id': 'An identifier that the platform gave for the call, exactly as it gave it.',
    'provared.error': "The error text that the agent's software was given, exactly as given.",
})
"""The reserved document names, and the exact text whose SHA-256 each one gives."""


REPEATABLE_DOCUMENT_NAMES = ('provared.trace-id', 'provared.request-id', 'provared.event-id')
"""The reserved names that may appear more than once in one record: an
identifier from each of several systems. Every other reserved name may
appear once at most."""


def is_unknown_reserved_document(name):
    """Whether a document name is reserved and not on the list: such a name is refused."""
    return isinstance(name, str) and name.startswith(RESERVED_DOCUMENT_PREFIX) and name not in DOCUMENT_NAMES


# A method is a token of RFC 9110, section 5.6.2: one or more of these.
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
# An address is taken exactly as it was sent, never rewritten: so it must
# already be in the form a request carries, an absolute http or https
# address of visible ASCII characters, with no fragment (which is never
# sent).
_ADDRESS = re.compile(r'https?://[\x21\x22\x24-\x7e]+')

_ABSENT = object()


def _member(r, name):
    if isinstance(r, dict):
        return r.get(name, _ABSENT)
    return getattr(r, name, _ABSENT)


def _body(value, path):
    if value is _ABSENT or value is None:
        return _ABSENT
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise Refusal('bad-field', f'{path}: must be the bytes of the body, as sent.')
    # The bytes themselves, read through the buffer, never a subclass's own __bytes__.
    return bytes(memoryview(value))


def _content_digest(data):
    # The Content-Digest field value of RFC 9530, with SHA-256 only; base64
    # with padding (RFC 4648, section 4), as a byte sequence of RFC 8941 is written.
    return 'sha-256=:' + base64.b64encode(sha256(data)).decode('ascii') + ':'


def _signature_base(components):
    # The signature base of RFC 9421, section 2.5: a line for each component,
    # "<identifier>: <value>" and a line feed, then the line
    # "@signature-params" with the list of the components and no parameters,
    # and no line feed after it. Nothing is signed with it.
    lines = ''.join(f'"{name}": {value}\n' for name, value in components)
    return lines + '"@signature-params": (' + ' '.join(f'"{name}"' for name, _ in components) + ')'


def _is_object(r):
    return r is not None and not isinstance(r, (str, bytes, bytearray, int, float, bool, list, tuple))


def http_request_base(r):
    """The text that the reserved name "provared.http-request" is made from.
    r: "method" and "url" exactly as sent, and "body" (bytes) where there is a body."""
    if not _is_object(r):
        raise Refusal('bad-field', 'The request must be an object.')
    method = _member(r, 'method')
    url = _member(r, 'url')
    given = _body(_member(r, 'body'), 'body')
    # The text itself, never a subclass's own way of writing it.
    method = str.__str__(method) if isinstance(method, str) else method
    url = str.__str__(url) if isinstance(url, str) else url
    if not isinstance(method, str) or not _TOKEN.fullmatch(method):
        raise Refusal('bad-field', 'method: must be the method of the request as sent, a token such as GET or POST.')
    if not isinstance(url, str) or not _ADDRESS.fullmatch(url):
        raise Refusal('bad-field', 'url: must be the address of the request as sent: an absolute http or https address of visible ASCII characters, with no fragment.')
    components = [('@method', method), ('@target-uri', url)]
    if given is not _ABSENT:
        components.append(('content-digest', _content_digest(given)))
    return _signature_base(components)


def http_response_base(r):
    """The text that the reserved name "provared.http-response" is made from.
    r: "status", and "body" (bytes) where there is a body."""
    if not _is_object(r):
        raise Refusal('bad-field', 'The answer must be an object.')
    status = _member(r, 'status')
    given = _body(_member(r, 'body'), 'body')
    # A whole number, whatever its type, as JavaScript reads one: a float
    # that equals a whole number is that whole number. True and False are
    # not numbers here. The value is read as the plain number, never through
    # a subclass's own methods.
    whole = None
    if isinstance(status, int) and not isinstance(status, bool):
        whole = int.__index__(status)
    elif isinstance(status, float) and float.is_integer(status):
        whole = float.__int__(status)
    if whole is None or not 100 <= whole <= 599:
        raise Refusal('bad-field', 'status: must be the status code of the answer, a whole number from 100 to 599.')
    components = [('@status', '%d' % whole)]
    if given is not _ABSENT:
        components.append(('content-digest', _content_digest(given)))
    return _signature_base(components)


def http_request_fingerprint(r):
    """The fingerprint of an HTTP request, for the document
    "provared.http-request": "method" and "url" exactly as sent, and "body"
    (bytes) where there is a body. Raises a Refusal, "bad-field", if the
    request is not as set out."""
    return fingerprint(utf8(http_request_base(r)))


def http_response_fingerprint(r):
    """The fingerprint of an HTTP answer, for the document
    "provared.http-response": "status", and "body" (bytes) where there is a
    body. Raises a Refusal, "bad-field", if the answer is not as set out."""
    return fingerprint(utf8(http_response_base(r)))


def identifier_fingerprint(identifier):
    """The fingerprint of an identifier or of an error text, exactly as given:
    SHA-256 of its UTF-8 bytes. For "provared.trace-id", "provared.request-id",
    "provared.event-id" and "provared.error". Raises a Refusal, "bad-field", if
    it is not text, is empty, or is not well-formed Unicode."""
    if not isinstance(identifier, str) or len(identifier) == 0:
        raise Refusal('bad-field', 'The identifier must be text of one character or more.')
    identifier = str.__str__(identifier)  # the text itself, never a subclass's own methods
    if not _well_formed(identifier):
        raise Refusal('bad-field', 'The identifier holds text that is not well-formed Unicode.')
    return fingerprint(utf8(identifier))
