# The approval: the person's own yes to one action, signed with the same
# passkey as the slip. Format description, section 17.

from . import _js
from . import fields as f
from .encoding import canonical_json, fingerprint, format_time, now_ms, random_id
from .jws import KINDS
from .slip import assemble_slip, prepare_passkey_record
from .stub import validate_request


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


def _length(value):
    """value.length in JavaScript: a text's UTF-16 units, a list's items, an
    object's own member "length"; nothing for any other value."""
    if isinstance(value, str):
        return _js.utf16_length(value)
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return value.get('length')
    return None


_ABSENT = object()
"""undefined: a member that is not there. The canonical form refuses it."""


def _member(value, name):
    """value[name] in JavaScript, for a value read from JSON: a member of an
    object, and nothing for any other value. Nothing at all has no members."""
    if value is None:
        raise TypeError(f'Cannot read properties of null (reading {name!r})')
    return value.get(name, _ABSENT) if isinstance(value, dict) else _ABSENT


def validate_approval_content(c):
    """Confirm every member of an approval's content."""
    f.members(c, ['action', 'id', 'slip', 'type', 'when'], ['amount', 'details', 'with'], 'approval')
    f.id_(c['id'], 'id')
    f.fingerprint_text(c['slip'], 'slip')
    validate_request(c)
    f.time(c['when'], 'when')


def request_of(c):
    """What an approval and a stub must agree on: the action, and the amount,
    the service and the documents, each present in both or in neither.

    c: the content of an approval or of a stub. Returns text.
    """
    request = {'action': _member(c, 'action')}
    for name in ('amount', 'details', 'with'):
        if isinstance(c, dict) and name in c:
            request[name] = c[name]
    return canonical_json(request)


def prepare_approval(fields):
    """Build the content of an approval and the challenge the person's passkey
    must sign.

    fields: "slip" (the fingerprint of the slip), "action", and where they
    apply "amount" ({"unit", "value"}), "with", "details" ([{"name",
    "sha256"}]) and "when" (milliseconds since 1970; defaults to now).
    Returns {"contentBytes", "payloadB64", "protectedB64", "challenge",
    "fingerprint"}: "fingerprint" is what the agent's stub must name as its
    approval.
    """
    given_id = fields.get('id')
    when = fields.get('when')
    content = {
        'type': KINDS['approval']['type'],
        'id': random_id() if given_id is None else given_id,
        'slip': fields.get('slip'),
        'action': fields.get('action'),
        'when': format_time(now_ms() if when is None else when),
    }
    if _truthy(fields.get('amount')):
        content['amount'] = fields['amount']
    if _truthy(fields.get('with')):
        content['with'] = fields['with']
    details = fields.get('details')
    if _truthy(details) and _truthy(_length(details)):
        content['details'] = details
    validate_approval_content(content)
    prepared = prepare_passkey_record('approval', content)
    return {**prepared, 'fingerprint': fingerprint(prepared['contentBytes'])}


def assemble_approval(prepared, authenticator_data, client_data_json, signature):
    """Put the passkey's three values with the prepared content: the signed
    approval. The values are stored exactly as the passkey returned them.

    prepared: from prepare_approval. Returns the approval record.
    """
    return assemble_slip(prepared, authenticator_data, client_data_json, signature)
