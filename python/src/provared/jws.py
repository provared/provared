# The signed envelope: JSON Web Signature (RFC 7515) in the general JSON
# serialisation (section 7.2.1), as the format description, sections 3.1 to
# 3.5, narrows it.
#
# Each layout is built in one place, here, and used by both the writers and
# the checker.

from . import _js
from .encoding import Refusal, canonical_json, fingerprint, from_base64url, from_utf8, parse_canonical, to_base64url, utf8

MAX_RECORD_BYTES = 65536
"""The largest record, in bytes."""


def _two(kind):
    return [f'{{"typ":"vnd.provared.{kind}.v0+json","alg":"Ed25519"}}', f'{{"typ":"vnd.provared.{kind}.v0+json","alg":"ML-DSA-87"}}']


def _passkey(kind):
    return [f'{{"typ":"vnd.provared.{kind}.v0+json","alg":"prova.red/webauthn/v0"}}']


KINDS = {
    'slip': {'type': 'provared.slip.v0', 'passkey': True, 'protected': _passkey('slip')},
    'stub': {'type': 'provared.stub.v0', 'protected': _two('stub')},
    'countersignature': {'type': 'provared.countersignature.v0', 'protected': _two('countersignature')},
    'approval': {'type': 'provared.approval.v0', 'passkey': True, 'protected': _passkey('approval')},
    'refusal': {'type': 'provared.refusal.v0', 'protected': _two('refusal')},
    'terms': {'type': 'provared.terms.v0', 'protected': _two('terms')},
    'cancellation': {'type': 'provared.cancellation.v0', 'passkey': True, 'protected': _passkey('cancellation')},
    'acknowledgement': {'type': 'provared.acknowledgement.v0', 'protected': _two('acknowledgement')},
    'vouching': {'type': 'provared.vouching.v0', 'protected': _two('vouching')},
    'withdrawal': {'type': 'provared.withdrawal.v0', 'protected': _two('withdrawal')},
    'pass': {'type': 'provared.pass.v0', 'protected': _two('pass')},
    'seal': {
        'type': 'provared.seal.v0',
        'protected': _two('seal') + ['{"typ":"vnd.provared.seal.v0+json","alg":"SLH-DSA-SHA2-256s"}'],
    },
}
"""The kinds of record. For each: the "type" of its content, and the exact
protected header of each signature, in order. A checker compares protected
headers byte for byte with these texts and interprets nothing else."""

_ALL_PROTECTED = {text: kind for kind, k in KINDS.items() for text in k['protected']}


def protected_headers(kind):
    """The protected headers of a kind, in base64url, in signature order."""
    return [to_base64url(utf8(text)) for text in KINDS[kind]['protected']]


def signing_input(protected_b64, payload_b64):
    """The bytes a signature covers (RFC 7515 section 5.1): the protected header
    in base64url, a full stop, the content in base64url."""
    return utf8(protected_b64 + '.' + payload_b64)


def record_size(record):
    """The size of a record, as the format description, section 3.1, measures it:
    the lengths of its "payload" and of every text value in its signature
    entries, added up."""
    payload = record.get('payload')
    size = _js.utf16_length(payload) if isinstance(payload, str) else 0
    signatures = record.get('signatures')
    if not isinstance(signatures, list):
        return size
    for s in signatures:
        if not isinstance(s, (dict, list)):
            continue
        values = s.values() if isinstance(s, dict) else s
        for v in values:
            size += _js.utf16_length(v) if isinstance(v, str) else 0
        header = s.get('header') if isinstance(s, dict) else None
        if isinstance(header, (dict, list)):
            for v in header.values() if isinstance(header, dict) else header:
                size += _js.utf16_length(v) if isinstance(v, str) else 0
    return size


def within_size(record):
    """A writer's check that what it has made is small enough to be accepted."""
    if record_size(record) > MAX_RECORD_BYTES:
        raise Refusal('too-large', 'The record would be larger than 65,536 bytes.')
    return record


def _exact_members(obj, names, what):
    if not isinstance(obj, dict):
        raise Refusal('bad-envelope', f'{what} must be an object.')
    have = _js.sort_strings(obj.keys())
    want = _js.sort_strings(names)
    if have != want:
        raise Refusal('bad-envelope', f'{what} must hold exactly: {", ".join(want)}.')


class ParsedRecord:
    __slots__ = ('kind', 'payload_b64', 'content_bytes', 'content', 'fingerprint', 'signatures')

    def __init__(self, kind, payload_b64, content_bytes, content, fp, signatures):
        self.kind = kind
        self.payload_b64 = payload_b64
        self.content_bytes = content_bytes
        self.content = content
        self.fingerprint = fp
        self.signatures = signatures


def parse_record(record, kind):
    """Read a record and confirm its envelope, its labels and the canonical form
    of its content. This checks no signature and no field of the content
    other than "type"."""
    expected = KINDS[kind]
    passkey = expected.get('passkey', False)
    _exact_members(record, ['payload', 'signatures'], 'A record')
    if not isinstance(record['payload'], str):
        raise Refusal('bad-envelope', '"payload" must be text.')
    if not isinstance(record['signatures'], list):
        raise Refusal('bad-envelope', '"signatures" must be a list.')

    # The size is measured before anything is decoded.
    if record_size(record) > MAX_RECORD_BYTES:
        raise Refusal('too-large', 'The record is larger than 65,536 bytes.')

    # Labels first: what kind of record does each signature say this is?
    signatures = []
    seen = []
    for s in record['signatures']:
        _exact_members(s, ['header', 'protected', 'signature'] if passkey else ['protected', 'signature'], 'A signature entry')
        if not isinstance(s['protected'], str) or not isinstance(s['signature'], str):
            raise Refusal('bad-envelope', '"protected" and "signature" must be text.')
        text = from_utf8(from_base64url(s['protected']), 'unknown-type')
        if text not in _ALL_PROTECTED:
            raise Refusal('unknown-type', 'A signature carries a label that is not one of the known labels.')
        if _ALL_PROTECTED[text] != kind:
            raise Refusal('payload-type-mismatch', f'A signature is labelled as a {_ALL_PROTECTED[text]}, but a {kind} is expected here.')
        seen.append(text)
        entry = {'protected_b64': s['protected'], 'signature': from_base64url(s['signature'])}
        if passkey:
            _exact_members(s['header'], ['authenticatorData', 'clientDataJSON'], 'The "header" of a passkey signature')
            entry['header'] = s['header']
        signatures.append(entry)
    if seen != expected['protected']:
        if passkey:
            message = f'A {kind} carries exactly one signature.'
        elif kind == 'seal':
            message = 'A seal carries exactly three signatures: Ed25519, ML-DSA-87, then SLH-DSA-SHA2-256s.'
        else:
            message = f'A {kind} carries exactly two signatures: Ed25519, then ML-DSA-87.'
        raise Refusal('bad-signatures-layout', message)

    content_bytes = from_base64url(record['payload'])
    content = parse_canonical(from_utf8(content_bytes, 'payload-not-canonical'))
    if not isinstance(content, dict):
        raise Refusal('bad-field', 'The content must be an object.')
    if content.get('type') != expected['type']:
        # Nothing from the content goes into the message: it is untrusted, and need not even be text.
        raise Refusal('payload-type-mismatch', f'The content does not say it is a {kind}, which is what is expected here.')
    return ParsedRecord(kind, record['payload'], content_bytes, content, fingerprint(content_bytes), signatures)


def encode_content(content):
    """Write content in the canonical form and return what a signer needs."""
    content_bytes = utf8(canonical_json(content))
    return content_bytes, to_base64url(content_bytes)
