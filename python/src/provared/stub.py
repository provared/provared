# The Stub (the receipt for one action) and the countersignature.
# Format description, sections 5 and 6.

from . import fields as f
from .encoding import fingerprint, format_time, now_ms, random_id, to_base64url
from .jws import KINDS, encode_content, parse_record, protected_headers, signing_input, within_size
from .keys import KEY_SET_METHODS
from .signatures import sign


def validate_stub_content(c):
    """Confirm every member of a stub's content (format description, section 5.1)."""
    f.members(c, ['action', 'id', 'seq', 'slip', 'type', 'when'], ['amount', 'approval', 'details', 'pass', 'previous', 'terms', 'with'], 'stub')
    f.id_(c['id'], 'id')
    f.fingerprint_text(c['slip'], 'slip')
    f.whole_number(c['seq'], 'seq')
    if c['seq'] == 0:
        if 'previous' in c:
            raise f.fail('previous', 'the first stub under a slip names no stub before it.')
    else:
        if 'previous' not in c:
            raise f.fail('previous', 'is missing.')
        f.fingerprint_text(c['previous'], 'previous')
    validate_request(c)
    if 'approval' in c:
        f.fingerprint_text(c['approval'], 'approval')
    if 'pass' in c:
        f.fingerprint_text(c['pass'], 'pass')
    if 'terms' in c:
        f.fingerprint_text(c['terms'], 'terms')
        if 'with' not in c:
            raise f.fail('terms', 'a stub that relies on the terms of a service must name the service.')
    f.time(c['when'], 'when')


def validate_request(c):
    """Confirm the members that say what was done, or what is asked for: the
    action, and where present the amount, the service and the documents. A
    stub, an approval and a refusal share them."""
    f.action_name(c['action'], 'action')
    if 'amount' in c:
        f.members(c['amount'], ['unit', 'value'], [], 'amount')
        f.unit(c['amount']['unit'], 'amount.unit')
        f.whole_number(c['amount']['value'], 'amount.value')
    if 'with' in c:
        f.short_name(c['with'], 'with')
    if 'details' in c:
        f.list_of(c['details'], 1, 32, 'details')
        for i, d in enumerate(c['details']):
            f.members(d, ['name', 'sha256'], [], f'details[{i}]')
            f.label(d['name'], f'details[{i}].name')
            f.fingerprint_text(d['sha256'], f'details[{i}].sha256')


def validate_countersignature_content(c):
    """Confirm every member of a countersignature's content (format description,
    section 6)."""
    f.members(c, ['stub', 'type', 'when'], [], 'countersignature')
    f.fingerprint_text(c['stub'], 'stub')
    f.time(c['when'], 'when')


# --- writing ---


def sign_with_key_set(kind, content, private_keys):
    """Sign content with a key set: two signatures side by side, Ed25519 then
    ML-DSA-87, each over its own signing input (format description, 3.9).
    Returns the record and its fingerprint."""
    content_bytes, payload_b64 = encode_content(content)
    headers = protected_headers(kind)
    signatures = []
    for i, alg in enumerate(KEY_SET_METHODS):
        signature = sign(alg, private_keys[i], signing_input(headers[i], payload_b64))
        signatures.append({'protected': headers[i], 'signature': to_base64url(signature)})
    return within_size({'payload': payload_b64, 'signatures': signatures}), fingerprint(content_bytes)


def write_stub(stub_fields, private_keys):
    """Write and sign a stub.

    stub_fields: "slip" (the fingerprint of the slip relied on); "after" (the
    stub before this one under the same slip, as {"seq", "fingerprint"}, or
    None for the first); "action"; and where they apply "amount" ({"unit",
    "value"}), "with" (the id of the service, as the slip names it),
    "details" (fingerprints of documents, never the documents), "approval",
    "terms", "pass" and "when" (milliseconds since 1970; defaults to now).
    private_keys: the agent's private keys, Ed25519 then ML-DSA-87.
    Returns {"record", "fingerprint", "seq"}.
    """
    after = stub_fields.get('after')
    seq = after['seq'] + 1 if after else 0
    when = stub_fields.get('when')
    given_id = stub_fields.get('id')
    content = {
        'type': KINDS['stub']['type'],
        'id': random_id() if given_id is None else given_id,
        'slip': stub_fields.get('slip'),
        'seq': seq,
        'action': stub_fields.get('action'),
        'when': format_time(now_ms() if when is None else when),
    }
    if after:
        content['previous'] = after['fingerprint']
    for name in ('amount', 'with', 'approval', 'terms', 'pass'):
        if stub_fields.get(name):
            content[name] = stub_fields[name]
    if stub_fields.get('details'):
        content['details'] = stub_fields['details']
    validate_stub_content(content)
    record, fp = sign_with_key_set('stub', content, private_keys)
    return {'record': record, 'fingerprint': fp, 'seq': seq}


def countersign(stub_record, private_keys, when=None):
    """Countersign a stub: the service's statement "this happened with me".

    The service should check the stub before it signs. This function only
    reads the stub's fingerprint; it does not judge the stub.
    """
    stub = parse_record(stub_record, 'stub')
    content = {'type': KINDS['countersignature']['type'], 'stub': stub.fingerprint, 'when': format_time(now_ms() if when is None else when)}
    validate_countersignature_content(content)
    return sign_with_key_set('countersignature', content, private_keys)[0]
