# The other side's voice: two records a service writes and signs itself.
# A refusal says "this agent asked for something, and we refused". Terms
# say which actions the service accepts from agents.
# Format description, sections 18 and 19.

from . import _js
from . import fields as f
from .actions import action_kind, is_never_name
from .encoding import format_time, now_ms, random_id
from .jws import KINDS
from .keys import check_key_set
from .stub import sign_with_key_set, validate_request

REFUSAL_REASONS = {
    'not-in-slip': 'The slip does not cover the action, or does not name this service.',
    'over-limit': 'The action would pass a limit of the slip.',
    'outside-valid-time': 'The slip was not in force at that time.',
    'slip-not-sound': 'The slip did not pass its check.',
    'needs-approval': "The slip asks for the person's approval, and none was shown.",
    'against-terms': "The service's terms for agents do not accept the action.",
    'other': 'Another reason.',
}
"""Why a service refused. A refusal gives exactly one of these."""


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


def _validate_by(by):
    f.members(by, ['keys', 'name'], [], 'by')
    f.label(by['name'], 'by.name')
    check_key_set(by['keys'], 'by.keys')


def validate_refusal_content(c):
    """Confirm every member of a refusal's content."""
    f.members(c, ['action', 'by', 'id', 'reason', 'slip', 'type', 'when'], ['amount'], 'refusal')
    f.id_(c['id'], 'id')
    f.fingerprint_text(c['slip'], 'slip')
    _validate_by(c['by'])
    # What was asked for is written down as it was asked, even a reserved
    # name that is not on the shared list: that may be why it was refused.
    f.short_name(c['action'], 'action')
    if 'amount' in c:
        validate_request({'action': 'x', 'amount': c['amount']})
    if not isinstance(c['reason'], str) or c['reason'] not in REFUSAL_REASONS:
        raise f.fail('reason', 'must be one of the listed reasons.')
    f.time(c['when'], 'when')


def validate_terms_content(c):
    """Confirm every member of a service's terms for agents."""
    f.members(c, ['accepts', 'by', 'id', 'never', 'type', 'validFrom', 'validUntil'], [], 'terms')
    f.id_(c['id'], 'id')
    _validate_by(c['by'])
    f.list_of(c['accepts'], 1, 64, 'accepts')
    for i, a in enumerate(c['accepts']):
        f.action_name(a, f'accepts[{i}]')
    if len(set(c['accepts'])) != len(c['accepts']):
        raise f.fail('accepts', 'an action name is repeated.')
    f.list_of(c['never'], 0, 16, 'never')
    for i, n in enumerate(c['never']):
        if not is_never_name(n):
            raise f.fail(f'never[{i}]', 'must be a listed kind of action or a listed rule of conduct.')
    if len(set(c['never'])) != len(c['never']):
        raise f.fail('never', 'a name is repeated.')
    for a in c['accepts']:
        if action_kind(a) in c['never']:
            raise f.fail('never', 'forbids a kind of action that the terms also accept.')
    start = f.time(c['validFrom'], 'validFrom')
    until = f.time(c['validUntil'], 'validUntil')
    if not (start < until):
        raise f.fail('validUntil', 'must be later than validFrom.')


def write_refusal(fields, private_keys):
    """Write and sign a refusal: the service's statement that an agent asked
    for something under a slip, and was refused.

    fields: "slip" (the fingerprint of the slip the agent showed), "by" (the
    service's public key set and its name, a label: {"keys", "name"}),
    "action" (what the agent asked for), "reason" (one of REFUSAL_REASONS),
    and where they apply "amount" ({"unit", "value"}) and "when"
    (milliseconds since 1970; defaults to now).
    private_keys: the service's private keys, Ed25519 then ML-DSA-87.
    Returns {"record", "fingerprint"}.
    """
    given_id = fields.get('id')
    when = fields.get('when')
    content = {
        'type': KINDS['refusal']['type'],
        'id': random_id() if given_id is None else given_id,
        'slip': fields.get('slip'),
        'by': fields.get('by'),
        'action': fields.get('action'),
        'reason': fields.get('reason'),
        'when': format_time(now_ms() if when is None else when),
    }
    if _truthy(fields.get('amount')):
        content['amount'] = fields['amount']
    validate_refusal_content(content)
    record, fp = sign_with_key_set('refusal', content, private_keys)
    return {'record': record, 'fingerprint': fp}


def write_terms(fields, private_keys):
    """Write and sign a service's terms for agents.

    fields: "by" (the service's public key set and its name, a label:
    {"keys", "name"}), "accepts" (the actions the service accepts from
    agents), "never" (kinds of action and rules of conduct the service asks
    agents to keep; defaults to none), "validFrom" and "validUntil".
    private_keys: the service's private keys, Ed25519 then ML-DSA-87.
    Returns {"record", "fingerprint"}.
    """
    given_id = fields.get('id')
    never = fields.get('never')
    content = {
        'type': KINDS['terms']['type'],
        'id': random_id() if given_id is None else given_id,
        'by': fields.get('by'),
        'accepts': fields.get('accepts'),
        'never': [] if never is None else never,
        'validFrom': fields.get('validFrom'),
        'validUntil': fields.get('validUntil'),
    }
    validate_terms_content(content)
    record, fp = sign_with_key_set('terms', content, private_keys)
    return {'record': record, 'fingerprint': fp}
