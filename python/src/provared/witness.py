# The witness statement: a party with a key set of its own (a witness)
# states that it saw a seal, that the seal extends every earlier seal of
# the same book it signed for, and that it will sign for no seal of that
# book that does not extend this one. It is signed with the witness's two
# keys. A statement sits beside its seal in the seal's book entry, as
# time-stamps do, or is handed to a checker beside a seal held elsewhere.
# Format description, section 29.
#
# There is no witness program in Python: a witness checks a seal's three
# signatures, and this library cannot check SLH-DSA.

from . import fields as f
from .encoding import format_time, now_ms, random_id
from .jws import KINDS
from .keys import check_key_set
from .stub import sign_with_key_set

MAX_WITNESSES = 4
"""The most witness statements one seal entry may hold, or that may be handed over with one seal."""


def validate_witness_content(c):
    """Confirm every member of a witness statement's content."""
    f.members(c, ['by', 'id', 'root', 'seal', 'size', 'type', 'when'], [], 'witness')
    f.id_(c['id'], 'id')
    f.fingerprint_text(c['seal'], 'seal')
    f.whole_number(c['size'], 'size')
    if c['size'] < 1:
        raise f.fail('size', 'must be 1 or more.')
    f.fingerprint_text(c['root'], 'root')
    f.members(c['by'], ['keys', 'name'], [], 'by')
    f.label(c['by']['name'], 'by.name')
    check_key_set(c['by']['keys'], 'by.keys')
    f.time(c['when'], 'when')


def write_witness(fields, private_keys):
    """Write and sign a witness statement for a seal. This only writes the
    statement: it does not check the seal.

    fields: "seal" (the seal's fingerprint), "size" and "root" (repeated
    from the seal), "by" (the witness's public key set and its name, a
    label: {"keys", "name"}), and where wanted "when" (milliseconds since
    1970; defaults to now). private_keys: the witness's private keys, or
    signers, Ed25519 then ML-DSA-87. A signer must hold the key "by" names.
    Returns {"record", "fingerprint"}.
    """
    given_id = fields.get('id')
    when = fields.get('when')
    content = {
        'type': KINDS['witness']['type'],
        'id': random_id() if given_id is None else given_id,
        'seal': fields.get('seal'),
        'size': fields.get('size'),
        'root': fields.get('root'),
        'by': fields.get('by'),
        'when': format_time(now_ms() if when is None else when),
    }
    validate_witness_content(content)
    record, fp = sign_with_key_set('witness', content, private_keys, content['by']['keys'])
    return {'record': record, 'fingerprint': fp}
