# The denial: the agent's own side states that it did not take an action
# that was asked for, and why. It is signed with the agent's two keys, or
# with the helper agent's under its pass. It is the agent's side's own
# word, and an agent can simply not write one.
# Format description, section 28.

from . import fields as f
from ._js import truthy
from .encoding import format_time, now_ms, random_id
from .jws import KINDS
from .stub import sign_with_key_set, validate_request

DENIAL_SOURCES = {
    'check': 'The check before acting (section 20) did not allow the action.',
    'person': 'The person refused, or gave no approval when asked.',
    'rule': 'A rule of the software around the agent, outside the slip.',
}
"""Who said no."""

FINDING_CODES = (
    'not-json', 'bad-envelope', 'bad-base64url', 'too-large', 'unknown-type', 'bad-signatures-layout', 'payload-not-canonical',
    'payload-type-mismatch', 'bad-field', 'bad-key', 'signature-invalid', 'passkey-wrong-type', 'passkey-challenge-mismatch',
    'passkey-origin-mismatch', 'passkey-rpid-mismatch', 'passkey-user-not-present', 'passkey-user-not-verified', 'passkey-bad-data',
    'issuer-not-expected', 'slip-missing', 'slip-unusable', 'chain-broken', 'time-went-backwards', 'duplicate-id', 'duplicate-slip',
    'countersignature-invalid', 'countersignature-wrong-stub', 'countersignature-not-possible', 'line-not-canonical', 'unknown-entry',
    'approval-mismatch', 'approval-reused', 'approval-invalid', 'approval-not-found', 'approval-dated-after-stub', 'terms-not-found',
    'terms-unusable', 'terms-mismatch', 'pass-missing', 'pass-mismatch', 'pass-too-deep', 'cover-invalid', 'cancellation-invalid',
    'cancellation-not-found', 'acknowledgement-mismatch', 'vouching-missing', 'seal-mismatch', 'seal-chain-broken', 'sealer-not-expected', 'book-cut-short', 'seal-not-in-book', 'witness-invalid',
    'dated-after-stamp', 'stamp-bad-data', 'stamp-wrong-data', 'stamp-invalid', 'headers-invalid', 'record-not-sound', 'proof-invalid',
    'root-mismatch', 'check-failed', 'action-not-allowed', 'party-not-allowed', 'outside-valid-time', 'amount-missing', 'over-limit',
    'over-each-limit', 'over-count-limit', 'over-period-limit', 'countersignature-missing', 'approval-missing', 'prohibited',
    'pass-not-allowed', 'pass-wider', 'after-cancellation', 'outside-terms',
)
"""The format's own list of finding codes: every code a checker or the check
before acting gives (format description, section 28; the same list is in
the list of threats, section 8). A denial whose source is "check" names its
reasons from this list."""

MAX_DENIAL_CODES = 16
"""The most finding codes one denial may name."""


def denial_codes(answer):
    """The reasons of a refusal by the check before acting, as a denial names
    them: the codes of its problems, then of its findings, each once, in that
    order, from the format's own list, at most 16. Where none is on the list,
    "check-failed"."""
    codes = []
    for p in [*answer['problems'], *answer['breaches']]:
        code = p.get('code') if isinstance(p, dict) else None
        if isinstance(code, str) and code in FINDING_CODES and code not in codes:
            codes.append(code)
    return codes[:MAX_DENIAL_CODES] if codes else ['check-failed']


def validate_denial_content(c):
    """Confirm every member of a denial's content."""
    f.members(c, ['action', 'id', 'slip', 'source', 'type', 'when'], ['amount', 'codes', 'details', 'pass', 'with'], 'denial')
    f.id_(c['id'], 'id')
    f.fingerprint_text(c['slip'], 'slip')
    if 'pass' in c:
        f.fingerprint_text(c['pass'], 'pass')
    # What was asked for is written down as it was asked, as in a refusal: a
    # reserved name that is not on the shared list may be why it was refused.
    f.short_name(c['action'], 'action')
    # The amount, the service and the documents as in a stub; the service
    # need not be one the slip names.
    validate_request({**c, 'action': 'x'})
    source = c['source']
    if not isinstance(source, str) or source not in DENIAL_SOURCES:
        raise f.fail('source', 'must be "check", "person" or "rule".')
    if source == 'check':
        if 'codes' not in c:
            raise f.fail('codes', 'is missing: a denial by the check before acting names its reasons.')
        f.list_of(c['codes'], 1, MAX_DENIAL_CODES, 'codes')
        for i, code in enumerate(c['codes']):
            if not isinstance(code, str) or code not in FINDING_CODES:
                raise f.fail(f'codes[{i}]', "must be a code from the format's own list of finding codes.")
        if len(set(c['codes'])) != len(c['codes']):
            raise f.fail('codes', 'a code is repeated.')
    elif 'codes' in c:
        raise f.fail('codes', 'only a denial by the check before acting names codes.')
    f.time(c['when'], 'when')


def write_denial(fields, private_keys):
    """Write and sign a denial: the agent's side states that it did not take an
    action that was asked for, and why. It is signed with the keys of the
    agent the slip names or, where the signer is a helper agent, with the
    keys the pass names.

    fields: "slip" (the fingerprint of the slip the agent acts under), for a
    helper agent "pass", "action" (what was asked for), where they apply
    "amount", "with" (the service asked for, as asked; it need not be one the
    slip names) and "details" (fingerprints of documents, never the
    documents), "source" ("check", "person" or "rule"), for "check" "codes"
    (1 to 16 finding codes, from FINDING_CODES), and "when" (milliseconds
    since 1970; defaults to now).
    private_keys: the agent's private keys, or signers (provared.signatures.Signer), Ed25519 then ML-DSA-87.
    Returns {"record", "fingerprint"}.
    """
    given_id = fields.get('id')
    when = fields.get('when')
    content = {
        'type': KINDS['denial']['type'],
        'id': random_id() if given_id is None else given_id,
        'slip': fields.get('slip'),
        'action': fields.get('action'),
        'source': fields.get('source'),
        'when': format_time(now_ms() if when is None else when),
    }
    for name in ('pass', 'amount', 'with'):
        if truthy(fields.get(name)):
            content[name] = fields[name]
    details = fields.get('details')
    if truthy(details) and truthy(len(details) if isinstance(details, (list, str)) else None):
        content['details'] = details
    if 'codes' in fields and fields['codes'] is not None:
        content['codes'] = fields['codes']
    validate_denial_content(content)
    record, fp = sign_with_key_set('denial', content, private_keys)
    return {'record': record, 'fingerprint': fp}
