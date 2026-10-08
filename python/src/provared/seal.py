# The Seal: whoever keeps a book signs its top fingerprint and its number of
# entries, and an outside time-stamp service states when that was.
# Format description, section 21.

import math

from . import _js
from . import fields as f
from .encoding import Refusal, fingerprint, format_time, from_base64url, now_ms, random_id, to_base64url, utf8
from .jws import KINDS, encode_content, protected_headers, signing_input, within_size
from .keys import SEAL_METHODS, check_seal_key_set
from .signatures import SLH, method_available, sign
from .timestamp import MAX_STAMP_BYTES
from .tree import tree_root

MAX_STAMPS = 4
"""The most time-stamps one seal may carry."""

CLOCK_ALLOWANCE_MS = 300 * 1000
"""How far a clock may differ, in milliseconds. A seal may be dated up to this
much after its time-stamp, and an entry up to this much after the
time-stamp that covers it, before the checker reports it."""


def validate_seal_content(c):
    """Confirm every member of a seal's content."""
    f.members(c, ['by', 'id', 'root', 'size', 'type', 'when'], ['previous'], 'seal')
    f.id_(c['id'], 'id')
    f.members(c['by'], ['keys', 'name'], [], 'by')
    f.label(c['by']['name'], 'by.name')
    check_seal_key_set(c['by']['keys'], 'by.keys')
    f.whole_number(c['size'], 'size')
    if c['size'] < 1:
        raise f.fail('size', 'must be 1 or more.')
    f.fingerprint_text(c['root'], 'root')
    if 'previous' in c:
        f.fingerprint_text(c['previous'], 'previous')
    f.time(c['when'], 'when')


def decode_stamps(stamps):
    """Confirm the time-stamps that sit beside a seal or a cancellation in an
    entry, and decode them. A time-stamp from a service is text: the
    service's answer in base64url. A block time-stamp is an object: the
    proof and the header of its block, each in base64url.

    Returns a list of {"kind": "service", "token"} and
    {"kind": "block", "header", "proof"}, with the bytes decoded.
    """
    f.list_of(stamps, 1, MAX_STAMPS, 'stamps')
    seen = set()
    items = []
    # Every place in the list is read by its number, so that a gap would be
    # refused as an empty place, not skipped (a list read from JSON has none).
    for i in range(len(stamps)):
        s = stamps[i]
        path = f'stamps[{i}]'

        def decode(text, most, what, path=path):
            if not isinstance(text, str) or _js.utf16_length(text) == 0 or _js.utf16_length(text) > math.ceil((most * 4) / 3):
                raise f.fail(path, what)
            try:
                return from_base64url(text)
            except Exception:
                raise Refusal('bad-base64url', 'A time-stamp is not base64url.') from None

        if isinstance(s, dict):
            f.members(s, ['block', 'proof'], [], path)
            item = {
                'kind': 'block',
                'header': decode(s['block'], 1024, 'must hold a block header of 80 bytes, in base64url.'),
                'proof': decode(s['proof'], MAX_STAMP_BYTES, 'must hold a proof in base64url, of at most 12,288 bytes.'),
            }
            key = f"{s['block']} {s['proof']}"
        else:
            item = {'kind': 'service', 'token': decode(s, MAX_STAMP_BYTES, 'must be a time-stamp in base64url, of at most 12,288 bytes.')}
            key = s
        if key in seen:
            raise f.fail('stamps', 'the same time-stamp is given twice.')
        seen.add(key)
        items.append(item)
    return items


def key_set_fingerprint(keys):
    """The fingerprint of a recorder's key set: how a person checking says which
    recorder they expect. It is the fingerprint of the list of keys, written
    in the canonical form. keys: a key set that has passed its check."""
    content_bytes, _ = encode_content(keys)
    return fingerprint(content_bytes)


def write_seal(book, seal_fields, private_keys):
    """Seal a book as it stands: sign its top fingerprint and its number of
    entries. The seal is then added to the book as its next entry, with any
    time-stamps beside it.

    seal_fields: "by" (the recorder's public key set and its name, a label),
    "previous" (the fingerprint of the seal before this one in the book, if
    there is one), "when" (milliseconds since 1970; defaults to now).
    private_keys: the recorder's private keys, in the order of the key set.

    A seal's third signature, SLH-DSA-SHA2-256s (FIPS 205), is not yet in
    "cryptography", so on this device the seal is checked and then refused
    with the error the JavaScript library gives where SLH-DSA is missing.
    Returns {"record", "fingerprint", "fingerprintBytes"} where it can sign.
    """
    lines = book.split('\n')
    if lines[-1] == '':
        lines.pop()
    given_id = seal_fields.get('id')
    when = seal_fields.get('when')
    content = {
        'type': KINDS['seal']['type'],
        'id': random_id() if given_id is None else given_id,
        'by': seal_fields.get('by'),
        'size': len(lines),
        'root': to_base64url(tree_root([utf8(line) for line in lines])),
        'when': format_time(now_ms() if when is None else when),
    }
    if seal_fields.get('previous'):
        content['previous'] = seal_fields['previous']
    validate_seal_content(content)
    if not method_available(SLH):
        raise RuntimeError('SLH-DSA is not built into this device.')
    content_bytes, payload_b64 = encode_content(content)
    headers = protected_headers('seal')
    signatures = []
    for i, alg in enumerate(SEAL_METHODS):
        signature = sign(alg, private_keys[i], signing_input(headers[i], payload_b64))
        signatures.append({'protected': headers[i], 'signature': to_base64url(signature)})
    name = fingerprint(content_bytes)
    return {'record': within_size({'payload': payload_b64, 'signatures': signatures}), 'fingerprint': name, 'fingerprintBytes': from_base64url(name)}
