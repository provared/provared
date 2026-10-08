# Records that begin or end someone's standing:
#   - a cancellation: the person ends a slip early, with their passkey;
#   - an acknowledgement: the agent's side states that it was handed a
#     cancellation;
#   - a vouching record: an organisation states whose key a key is;
#   - a withdrawal: the organisation ends a vouching record.
# Format description, sections 22, 23 and 26.

from . import _js
from . import fields as f
from .encoding import fingerprint, format_time, now_ms, random_id
from .jws import KINDS
from .keys import PASSKEY_METHODS, check_key, check_key_set, check_seal_key_set
from .slip import assemble_slip, prepare_passkey_record
from .stub import sign_with_key_set

VOUCHED_KINDS = {
    'person': 'A person, known by the public key of their passkey.',
    'agent': 'An agent, known by its two keys.',
    'service': 'A service, known by its two keys.',
    'recorder': 'A recorder, known by its three keys.',
}
"""What a vouching record can vouch for, and the keys each kind has."""


def _truthy(value):
    """Whether JavaScript counts a value as true: anything but nothing, false,
    0 and the empty text. An empty object or list counts as true."""
    if value is None or value is False:
        return False
    if _js.is_number(value):
        return value == value and value != 0
    if isinstance(value, str):
        return value != ''
    return True


def validate_cancellation_content(c):
    """Confirm every member of a cancellation's content."""
    f.members(c, ['id', 'slip', 'type', 'when'], [], 'cancellation')
    f.id_(c['id'], 'id')
    f.fingerprint_text(c['slip'], 'slip')
    f.time(c['when'], 'when')


def validate_acknowledgement_content(c):
    """Confirm every member of an acknowledgement's content."""
    f.members(c, ['cancellation', 'id', 'slip', 'type', 'when'], ['pass'], 'acknowledgement')
    f.id_(c['id'], 'id')
    f.fingerprint_text(c['slip'], 'slip')
    f.fingerprint_text(c['cancellation'], 'cancellation')
    if 'pass' in c:
        f.fingerprint_text(c['pass'], 'pass')
    f.time(c['when'], 'when')


def validate_vouching_content(c):
    """Confirm every member of a vouching record's content."""
    f.members(c, ['by', 'for', 'id', 'type', 'validFrom', 'validUntil', 'when'], [], 'vouching')
    f.id_(c['id'], 'id')
    f.members(c['by'], ['keys', 'name'], [], 'by')
    f.label(c['by']['name'], 'by.name')
    check_key_set(c['by']['keys'], 'by.keys')
    who = c['for']
    if not isinstance(who, dict) or not isinstance(who.get('kind'), str) or who['kind'] not in VOUCHED_KINDS:
        raise f.fail('for.kind', 'must be "person", "agent", "service" or "recorder".')
    if who['kind'] == 'person':
        f.members(who, ['key', 'kind', 'name'], [], 'for')
        check_key(who['key'], PASSKEY_METHODS, 'for.key')
    else:
        f.members(who, ['keys', 'kind', 'name'], [], 'for')
        if who['kind'] == 'recorder':
            check_seal_key_set(who['keys'], 'for.keys')
        else:
            check_key_set(who['keys'], 'for.keys')
    f.label(who['name'], 'for.name')
    start = f.time(c['validFrom'], 'validFrom')
    until = f.time(c['validUntil'], 'validUntil')
    if not (start < until):
        raise f.fail('validUntil', 'must be later than validFrom.')
    f.time(c['when'], 'when')


def validate_withdrawal_content(c):
    """Confirm every member of a withdrawal's content."""
    f.members(c, ['id', 'type', 'vouching', 'when'], [], 'withdrawal')
    f.id_(c['id'], 'id')
    f.fingerprint_text(c['vouching'], 'vouching')
    f.time(c['when'], 'when')


def prepare_cancellation(fields):
    """Build the content of a cancellation and the challenge the person's
    passkey must sign.

    fields: "slip" (the fingerprint of the slip to cancel) and "when"
    (milliseconds since 1970; defaults to now). Returns {"contentBytes",
    "payloadB64", "protectedB64", "challenge", "fingerprint"}.
    """
    given_id = fields.get('id')
    when = fields.get('when')
    content = {
        'type': KINDS['cancellation']['type'],
        'id': random_id() if given_id is None else given_id,
        'slip': fields.get('slip'),
        'when': format_time(now_ms() if when is None else when),
    }
    validate_cancellation_content(content)
    prepared = prepare_passkey_record('cancellation', content)
    return {**prepared, 'fingerprint': fingerprint(prepared['contentBytes'])}


def assemble_cancellation(prepared, authenticator_data, client_data_json, signature):
    """Put the passkey's three values with the prepared content: the signed
    cancellation.

    prepared: from prepare_cancellation. Returns the cancellation record.
    """
    return assemble_slip(prepared, authenticator_data, client_data_json, signature)


def write_acknowledgement(fields, private_keys):
    """Write and sign an acknowledgement: the statement of the agent's side
    that it was handed the person's cancellation of a slip, and when. It is
    signed with the keys of the agent the slip names or, where the signer is
    a helper agent, with the keys the pass names.

    fields: "slip" (the fingerprint of the slip that was cancelled),
    "cancellation" (the fingerprint of the cancellation), for a helper agent
    "pass" (the fingerprint of the pass it acts under), and "when" (when the
    cancellation was handed over, in milliseconds since 1970; defaults to
    now).
    private_keys: the agent's private keys, Ed25519 then ML-DSA-87.
    Returns {"record", "fingerprint"}.
    """
    given_id = fields.get('id')
    when = fields.get('when')
    content = {
        'type': KINDS['acknowledgement']['type'],
        'id': random_id() if given_id is None else given_id,
        'slip': fields.get('slip'),
        'cancellation': fields.get('cancellation'),
        'when': format_time(now_ms() if when is None else when),
    }
    if _truthy(fields.get('pass')):
        content['pass'] = fields['pass']
    validate_acknowledgement_content(content)
    record, fp = sign_with_key_set('acknowledgement', content, private_keys)
    return {'record': record, 'fingerprint': fp}


def write_vouching(fields, private_keys):
    """Write and sign a vouching record: an organisation's statement that a
    key belongs to a name.

    fields: "by" (the organisation's public key set and its name, a label:
    {"keys", "name"}), "for" (whom it vouches for: {"kind", "name"} with
    "key" for a person, or "keys" otherwise), "validFrom", "validUntil" and
    "when" (milliseconds since 1970; defaults to now).
    private_keys: the organisation's private keys, Ed25519 then ML-DSA-87.
    Returns {"record", "fingerprint"}.
    """
    given_id = fields.get('id')
    when = fields.get('when')
    content = {
        'type': KINDS['vouching']['type'],
        'id': random_id() if given_id is None else given_id,
        'by': fields.get('by'),
        'for': fields.get('for'),
        'validFrom': fields.get('validFrom'),
        'validUntil': fields.get('validUntil'),
        'when': format_time(now_ms() if when is None else when),
    }
    validate_vouching_content(content)
    record, fp = sign_with_key_set('vouching', content, private_keys)
    return {'record': record, 'fingerprint': fp}


def write_withdrawal(fields, private_keys):
    """Write and sign a withdrawal: the organisation ends a vouching record.

    fields: "vouching" (the fingerprint of the vouching record) and "when"
    (milliseconds since 1970; defaults to now).
    private_keys: the private keys of the organisation that made the
    vouching record.
    Returns {"record", "fingerprint"}.
    """
    given_id = fields.get('id')
    when = fields.get('when')
    content = {
        'type': KINDS['withdrawal']['type'],
        'id': random_id() if given_id is None else given_id,
        'vouching': fields.get('vouching'),
        'when': format_time(now_ms() if when is None else when),
    }
    validate_withdrawal_content(content)
    record, fp = sign_with_key_set('withdrawal', content, private_keys)
    return {'record': record, 'fingerprint': fp}
