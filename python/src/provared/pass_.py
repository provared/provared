# Passing a slip on: an agent hands part of its permission to a helper
# agent. Format description, section 25.
#
# The module is named "pass_" because "pass" is a word of Python itself.

from . import _js
from . import fields as f
from .encoding import format_time, now_ms, random_id
from .jws import KINDS
from .keys import check_key_set
from .slip import validate_limits
from .stub import sign_with_key_set

MAX_PASSES = 10
"""The most times a slip may let its permission be passed on."""


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


def validate_pass_content(c):
    """Confirm every member of a pass's content."""
    f.members(c, ['actions', 'id', 'limits', 'slip', 'to', 'type', 'validFrom', 'validUntil', 'when'], ['from'], 'pass')
    f.id_(c['id'], 'id')
    f.fingerprint_text(c['slip'], 'slip')
    if 'from' in c:
        f.fingerprint_text(c['from'], 'from')
    f.members(c['to'], ['keys', 'name'], [], 'to')
    f.label(c['to']['name'], 'to.name')
    check_key_set(c['to']['keys'], 'to.keys')
    f.list_of(c['actions'], 1, 64, 'actions')
    for i, a in enumerate(c['actions']):
        f.action_name(a, f'actions[{i}]')
    if len(set(c['actions'])) != len(c['actions']):
        raise f.fail('actions', 'an action name is repeated.')
    validate_limits(c['actions'], c['limits'])
    start = f.time(c['validFrom'], 'validFrom')
    until = f.time(c['validUntil'], 'validUntil')
    if not (start < until):
        raise f.fail('validUntil', 'must be later than validFrom.')
    f.time(c['when'], 'when')


def write_pass(fields, private_keys):
    """Write and sign a pass: the agent that holds a permission hands part of
    it to a helper agent.

    fields: "slip" (the fingerprint of the slip); "from" (the fingerprint of
    the pass the signer itself acts under; absent when the signer is the
    slip's own agent); "to" (the helper agent's public key set and its name,
    a label: {"keys", "name"}); "actions" (what the helper may do: no more
    than the signer may); "limits" (limits for the helper, in the form a slip
    uses; defaults to none); "validFrom", "validUntil" and "when"
    (milliseconds since 1970; defaults to now).
    private_keys: the private keys of the agent that passes on, Ed25519 then
    ML-DSA-87.
    Returns {"record", "fingerprint"}.
    """
    given_id = fields.get('id')
    limits = fields.get('limits')
    when = fields.get('when')
    content = {
        'type': KINDS['pass']['type'],
        'id': random_id() if given_id is None else given_id,
        'slip': fields.get('slip'),
        'to': fields.get('to'),
        'actions': fields.get('actions'),
        'limits': [] if limits is None else limits,
        'validFrom': fields.get('validFrom'),
        'validUntil': fields.get('validUntil'),
        'when': format_time(now_ms() if when is None else when),
    }
    if _truthy(fields.get('from')):
        content['from'] = fields['from']
    validate_pass_content(content)
    record, fp = sign_with_key_set('pass', content, private_keys)
    return {'record': record, 'fingerprint': fp}
