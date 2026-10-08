# The Slip: the permission a person signs with a passkey.
# Format description, section 4.

import re

from . import _js
from . import fields as f
from .actions import action_kind, is_never_name
from .cover import cover_members, uncover
from .encoding import Refusal, from_base64url, problem_from, random_id, sha256, to_base64url
from .jws import KINDS, encode_content, parse_record, protected_headers, signing_input, within_size
from .keys import PASSKEY_METHODS, check_key, check_key_set, thumbprint
from .webauthn import check_assertion

_SLIP_MEMBERS = ['actions', 'agent', 'id', 'issuer', 'limits', 'never', 'purpose', 'requires', 'type', 'validFrom', 'validUntil', 'with']
_LIMIT_KINDS = ['count', 'each', 'max']
_MAX_PERIOD_SECONDS = 366 * 86400
"""The longest period a limit may name: 366 days."""

# --- the address of the page a slip was signed on ---
#
# By an exact rule that any checker can follow without a reader of web
# addresses or tables of Unicode: "https://" (or "http://" for localhost),
# a host, a port only if it is not the scheme's own, and nothing more. A
# host is labels of lower-case letters, digits and hyphens, separated by
# full stops; no label begins or ends with a hyphen, and the last is not
# all digits. A browser writes a page's address in exactly this form, with
# a name in another script written in its "xn--" form, which the rule takes
# as it is.

_ORIGIN = re.compile(r'(https|http)://([a-z0-9.-]{1,253})(?::([1-9][0-9]{0,4}))?')
_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
_DIGITS = re.compile(r'[0-9]+')
_RP_ID = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?')


def _check_origin(origin, rp_id):
    f.text(origin, 1, 300, 'issuer.origin')
    if not isinstance(rp_id, str) or not _RP_ID.fullmatch(rp_id):
        raise f.fail('issuer.rpId', 'must be a website name in lower case, such as example.org.')
    m = _ORIGIN.fullmatch(origin)
    labels = m.group(2).split('.') if m else []
    port = int(m.group(3)) if m and m.group(3) is not None else None
    if (
        not m
        or not all(_LABEL.fullmatch(label) for label in labels)
        or _DIGITS.fullmatch(labels[-1])
        or (port is not None and (port > 65535 or port == (443 if m.group(1) == 'https' else 80)))
    ):
        raise f.fail(
            'issuer.origin',
            'must be the address of a page: https://, a website name in lower case, a port only if it is needed, and nothing more, such as https://sign.example.org.',
        )
    scheme, host = m.group(1), m.group(2)
    if not (scheme == 'https' or (scheme == 'http' and host == 'localhost')):
        raise f.fail('issuer.origin', 'must begin https://, or http://localhost.')
    if not (host == rp_id or host.endswith('.' + rp_id)):
        raise f.fail('issuer.origin', 'must be on the website that issuer.rpId names.')


def validate_limits(actions, limits):
    """Confirm a list of limits against the actions it may name (format
    description, section 4.1). A slip and a pass share it. Returns a check
    that every amount for one action is in one unit, to use on what follows."""
    # Every amount named for one action, in a limit or a condition, is in one
    # unit: a stub gives one amount.
    units = {}

    def one_unit(action, unit, path):
        f.unit(unit, path)
        if action in units and units[action] != unit:
            raise f.fail(path, 'every amount for one action must be in the same unit.')
        units[action] = unit

    f.list_of(limits, 0, 64, 'limits')
    limits_seen = set()
    for i, limit in enumerate(limits):
        p = f'limits[{i}]'
        f.members(limit, ['action'], ['count', 'each', 'max', 'per', 'unit'], p)
        if limit['action'] not in actions:
            raise f.fail(f'{p}.action', "must be one of the slip's actions.")
        kinds = [k for k in _LIMIT_KINDS if k in limit]
        if len(kinds) != 1:
            raise f.fail(p, 'must hold exactly one of "max", "each" and "count".')
        kind = kinds[0]
        f.whole_number(limit[kind], f'{p}.{kind}')
        if kind == 'count':
            if 'unit' in limit:
                raise f.fail(f'{p}.unit', 'a count of actions has no unit.')
            if limit['count'] < 1:
                raise f.fail(f'{p}.count', 'must be 1 or more.')
        else:
            if 'unit' not in limit:
                raise f.fail(p, '"unit" is missing.')
            one_unit(limit['action'], limit['unit'], f'{p}.unit')
        if 'per' in limit:
            if kind == 'each':
                raise f.fail(f'{p}.per', 'a limit on each action has no period.')
            f.whole_number(limit['per'], f'{p}.per')
            if limit['per'] < 1 or limit['per'] > _MAX_PERIOD_SECONDS:
                raise f.fail(f'{p}.per', 'must be from 1 second to 366 days, in seconds.')
        key = (limit['action'], kind, int(limit['per']) if 'per' in limit else None)
        if key in limits_seen:
            raise f.fail(p, 'the same kind of limit is given twice for one action.')
        limits_seen.add(key)
    return one_unit


COVERABLE = ['issuer.name', 'agent.name', 'purpose', 'with.name']
"""What a slip may cover: the names in it, and its purpose (format description, section 24)."""

_WITH_PATH = re.compile(r'with\[[0-9]+\]')


def validate_slip_content(c, places=None, named=False):
    """Confirm every member of a slip's content (format description, section
    4.1). Returns the fields that are covered and were not revealed, for
    example "issuer.name". Raises a Refusal "bad-field" or "bad-key"."""
    if places is None:
        places = {}
    # Only a name or the purpose may be covered, each in its own object. A
    # list of covered fields there holds exactly one fingerprint: that of the
    # one field. So a field is absent only where its fingerprint stands in
    # its place, and nothing can be shown as covered that is not.
    covered_now = []

    def may_lack(obj, path, name):
        place = places.get(path)
        if not place or place['covered'] != 1:
            return []
        if isinstance(obj, dict) and name in obj:
            raise f.fail(path or 'slip', 'holds a field and, as well, a fingerprint that stands in for it.')
        covered_now.append(name if path == '' else f'{path}.{name}')
        return [name]

    for path, place in places.items():
        if path == '':
            name = 'purpose'
        elif path in ('issuer', 'agent') or _WITH_PATH.fullmatch(path):
            name = 'name'
        else:
            name = None
        if name is None or any(r != name for r in place['revealed']):
            raise f.fail(path or 'slip', 'only a name or the purpose of a slip may be covered.')
        if place['covered'] + len(place['revealed']) != 1:
            raise f.fail(path or 'slip', 'a list of covered fields in a slip holds exactly one fingerprint.')
    if (len(places) > 0) != named:
        raise f.fail('slip', '"_sd_alg" is given where a field is covered, and only there.')
    lacks_purpose = may_lack(c, '', 'purpose')
    f.members(c, [m for m in _SLIP_MEMBERS if m not in lacks_purpose], ['passes'], 'slip')
    f.id_(c['id'], 'id')
    # How many times the permission may be passed on to a helper agent. Absent: not at all.
    if 'passes' in c:
        f.whole_number(c['passes'], 'passes')
        if c['passes'] < 1 or c['passes'] > 10:
            raise f.fail('passes', 'must be from 1 to 10; leave it out if the permission may not be passed on.')

    lacks_issuer_name = may_lack(c['issuer'], 'issuer', 'name')
    f.members(c['issuer'], [m for m in ['key', 'name', 'origin', 'rpId'] if m not in lacks_issuer_name], [], 'issuer')
    if not lacks_issuer_name:
        f.label(c['issuer']['name'], 'issuer.name')
    check_key(c['issuer']['key'], PASSKEY_METHODS, 'issuer.key')
    _check_origin(c['issuer']['origin'], c['issuer']['rpId'])

    lacks_agent_name = may_lack(c['agent'], 'agent', 'name')
    f.members(c['agent'], [m for m in ['keys', 'name'] if m not in lacks_agent_name], ['software'], 'agent')
    if not lacks_agent_name:
        f.label(c['agent']['name'], 'agent.name')
    check_key_set(c['agent']['keys'], 'agent.keys')
    if 'software' in c['agent']:
        f.list_of(c['agent']['software'], 1, 16, 'agent.software')
        for i, s in enumerate(c['agent']['software']):
            f.members(s, ['name', 'sha256'], [], f'agent.software[{i}]')
            f.label(s['name'], f'agent.software[{i}].name')
            f.fingerprint_text(s['sha256'], f'agent.software[{i}].sha256')

    f.list_of(c['actions'], 1, 64, 'actions')
    for i, a in enumerate(c['actions']):
        f.action_name(a, f'actions[{i}]')
    if len(set(c['actions'])) != len(c['actions']):
        raise f.fail('actions', 'an action name is repeated.')

    one_unit = validate_limits(c['actions'], c['limits'])

    f.list_of(c['requires'], 0, 64, 'requires')
    requires_seen = set()
    for i, r in enumerate(c['requires']):
        p = f'requires[{i}]'
        f.members(r, ['need'], ['above', 'action', 'unit'], p)
        if r['need'] not in ('approval', 'countersignature') or not isinstance(r['need'], str):
            raise f.fail(f'{p}.need', 'must be "approval" or "countersignature".')
        if 'action' in r and not _includes(c['actions'], r['action']):
            raise f.fail(f'{p}.action', "must be one of the slip's actions.")
        if ('above' in r) != ('unit' in r):
            raise f.fail(p, '"above" and "unit" come together.')
        if 'above' in r:
            if 'action' not in r:
                raise f.fail(p, '"above" needs an "action".')
            f.whole_number(r['above'], f'{p}.above')
            one_unit(r['action'], r['unit'], f'{p}.unit')
        key = (r['need'], r['action'] if 'action' in r else None)
        if key in requires_seen:
            raise f.fail(p, 'the same condition is given twice.')
        requires_seen.add(key)

    f.list_of(c['never'], 0, 16, 'never')
    for i, n in enumerate(c['never']):
        if not is_never_name(n):
            raise f.fail(f'never[{i}]', 'must be a listed kind of action or a listed rule of conduct.')
    if len(set(c['never'])) != len(c['never']):
        raise f.fail('never', 'a name is repeated.')
    for a in c['actions']:
        if action_kind(a) in c['never']:
            raise f.fail('never', 'forbids a kind of action that the slip also allows.')

    f.list_of(c['with'], 0, 64, 'with')
    ids = set()
    for i, service in enumerate(c['with']):
        lacks_name = may_lack(service, f'with[{i}]', 'name')
        f.members(service, [m for m in ['id', 'name'] if m not in lacks_name], ['keys'], f'with[{i}]')
        f.short_name(service['id'], f'with[{i}].id')
        if service['id'] in ids:
            raise f.fail(f'with[{i}].id', 'a service id is repeated.')
        ids.add(service['id'])
        if not lacks_name:
            f.label(service['name'], f'with[{i}].name')
        if 'keys' in service:
            check_key_set(service['keys'], f'with[{i}].keys')

    start = f.time(c['validFrom'], 'validFrom')
    until = f.time(c['validUntil'], 'validUntil')
    if not (start < until):
        raise f.fail('validUntil', 'must be later than validFrom.')
    if not lacks_purpose:
        f.text(c['purpose'], 1, 1000, 'purpose')
    return covered_now


def _includes(items, value):
    """Array.prototype.includes, which compares without converting types."""
    return any(type(x) is type(value) and x == value for x in items)


def check_passkey_signature(parsed, issuer, without=()):
    """Check the passkey signature on a record (a slip, an approval or a
    cancellation) against the issuer a slip names (format description,
    section 4.4). Returns 'valid' or 'unavailable'; raises a Refusal."""
    only = parsed.signatures[0]
    try:
        authenticator_data = from_base64url(only['header']['authenticatorData'])
        client_data_json = from_base64url(only['header']['clientDataJSON'])
    except Refusal:
        raise Refusal('passkey-bad-data', 'The passkey values stored with the record are not base64url.') from None
    return check_assertion(
        issuer['key'],
        issuer['rpId'],
        issuer['origin'],
        signing_input(only['protected_b64'], parsed.payload_b64),
        authenticator_data,
        client_data_json,
        only['signature'],
        without,
    )


def prepare_passkey_record(kind, content):
    """Build the challenge a passkey must sign for a record's content."""
    content_bytes, payload_b64 = encode_content(content)
    # Leave room for what the passkey returns, so the signed record still fits.
    within_size({'payload': payload_b64, 'signatures': [{'signature': 'A' * 2048}]})
    protected_b64 = protected_headers(kind)[0]
    return {
        'contentBytes': content_bytes,
        'payloadB64': payload_b64,
        'protectedB64': protected_b64,
        'challenge': sha256(signing_input(protected_b64, payload_b64)),
    }


_UNDEFINED = object()


def check_slip(record, options=None, disclosures=_UNDEFINED):
    """Check one slip (format description, section 4.4).

    options: "issuerKeys" (thumbprints of the issuer keys the checker
    expects), "withoutMethods", "disclosures" (for covered fields: the
    disclosures handed over, by the fingerprint of the record they belong
    to). disclosures: the disclosures for this slip, where they come with it
    (a page of a Show).
    """
    result = {
        'kind': 'slip',
        'fingerprint': None,
        'problems': [],
        'notes': [],
        'signature': {'method': 'passkey', 'alg': None, 'state': 'unchecked'},
        'issuerKey': None,
        'content': None,
        'covered': [],
        'disclosureProblems': [],
    }
    try:
        if not isinstance(options, dict):
            options = {}
        parsed = parse_record(record, 'slip')
        result['fingerprint'] = parsed.fingerprint
        # Covered fields: put back what was revealed, by the standard's own steps.
        handed = options.get('disclosures')
        beside = handed[parsed.fingerprint] if isinstance(handed, dict) and parsed.fingerprint in handed else []
        # Those that come with the slip (a page of a Show) and those handed
        # over beside it are used together; one given both ways counts once.
        for_this = beside if disclosures is _UNDEFINED or disclosures is None else disclosures
        if disclosures is not _UNDEFINED and isinstance(disclosures, list) and (not isinstance(beside, list) or len(beside) > 0):
            for_this = [*disclosures, *(d for d in beside if not _js.includes(disclosures, d))] if isinstance(beside, list) else beside

        # A slip narrows the standard: no covered item of a list, and every
        # disclosure in the canonical form.
        def reveal(given):
            content, places, named = uncover(parsed.content, given, list_items=False, canonical=True)
            return content, validate_slip_content(content, places, named)

        try:
            content, covered = reveal(for_this)
        except Exception as e:
            # What a slip is must not depend on what is handed over with it. If
            # the slip is sound with its fields covered, the fault lies in the
            # disclosures: they are not used, and that is reported apart.
            if isinstance(for_this, list) and len(for_this) == 0:
                raise
            content, covered = reveal([])
            result['disclosureProblems'].append(problem_from(e))
        result['covered'] = covered
        result['content'] = content
        issuer = content['issuer']
        result['signature']['method'] = f"passkey ({issuer['key']['alg']})"
        result['signature']['alg'] = issuer['key']['alg']
        result['issuerKey'] = thumbprint(issuer['key'])

        result['signature']['state'] = 'invalid'
        # As everywhere else, only a list counts as a list of methods to treat as not built in.
        without = options.get('withoutMethods')
        result['signature']['state'] = check_passkey_signature(parsed, issuer, without if isinstance(without, list) else [])
        if result['signature']['state'] == 'unavailable':
            result['notes'].append(f"This device cannot check the passkey's signing method ({issuer['key']['alg']}).")

        if isinstance(options.get('issuerKeys'), list):
            if result['issuerKey'] not in options['issuerKeys']:
                raise Refusal('issuer-not-expected', 'The slip was signed by a passkey other than the ones expected.')
        else:
            result['notes'].append("The issuer's key was not compared with a key you already trust. The name on the slip is only a label.")
    except Exception as e:
        result['problems'].append(problem_from(e))
    return result


# --- writing a slip ---


def prepare_slip(slip_fields, cover=()):
    """Build the content of a new slip and the challenge a passkey must sign
    (format description, section 4.2, steps 1 and 2).

    slip_fields: every member of the slip except "type"; "id" is made if
    absent. cover: the fields to cover, from COVERABLE. Returns the prepared
    slip; its "disclosures" reveal the covered fields. Keep them beside the
    slip, and hand over only the ones a reader needs.
    """
    # A slip with no conditions and no prohibitions says so with empty lists.
    given_id = slip_fields.get('id')
    content = {'requires': [], 'never': [], **slip_fields, 'type': KINDS['slip']['type'], 'id': random_id() if given_id is None else given_id}
    validate_slip_content(content)
    cover = list(cover) if isinstance(cover, (list, tuple)) else []
    if any(name not in COVERABLE for name in cover):
        raise f.fail('cover', 'only a name or the purpose of a slip may be covered.')
    disclosures = []

    def hide(obj, names):
        out, made = cover_members(obj, names)
        disclosures.extend(made)
        return out

    if 'issuer.name' in cover:
        content['issuer'] = hide(content['issuer'], ['name'])
    if 'agent.name' in cover:
        content['agent'] = hide(content['agent'], ['name'])
    if 'with.name' in cover:
        content['with'] = [hide(service, ['name']) for service in content['with']]
    if 'purpose' in cover:
        content = hide(content, ['purpose'])
    # The fingerprint method is named, as the standard allows, wherever anything is covered.
    if disclosures:
        content['_sd_alg'] = 'sha-256'
    return {**prepare_passkey_record('slip', content), 'disclosures': disclosures}


def assemble_slip(prepared, authenticator_data, client_data_json, signature):
    """Put the passkey's three values with the prepared content: the signed slip
    (format description, sections 4.2 step 4 and 4.3). The values are stored
    exactly as the passkey returned them."""
    return within_size({
        'payload': prepared['payloadB64'],
        'signatures': [
            {
                'protected': prepared['protectedB64'],
                'header': {
                    'authenticatorData': to_base64url(authenticator_data),
                    'clientDataJSON': to_base64url(client_data_json),
                },
                'signature': to_base64url(signature),
            }
        ],
    })
