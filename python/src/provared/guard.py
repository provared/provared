# The check before acting: would this action be outside the slip?
#
# The software around an agent can ask this before each action, and stop the
# action when the answer is no. It uses the same comparison as the checker
# (compare.py), so nothing is allowed here that the checker would report
# afterwards. It refuses more in one case only: an action that would add to
# a period which a stub dated after it already overfills. It writes
# nothing and changes nothing.

from collections.abc import Mapping

from . import fields as f
from .book import MAX_ENTRIES, MAX_LINE_BYTES, _Ids, check_approval_record, check_book_keeping_state, fixed_options, keys_of, pass_as_slip
from .compare import compare_with_slip
from .encoding import Refusal, canonical_json, format_time, nan_time, now_ms, problem_from, utf8
from .stub import validate_request


def _not_sound(why):
    return Refusal('record-not-sound', why)


# An upper bound on the line that the record of an action will make: the
# stub with its two signatures, the approval that goes with it, and the
# other side's countersignature. A line of a book may not be longer than
# 131,072 bytes, and an action whose record would not fit is not allowed.
_STUB_BOUND = 6700 + 600
_COUNTERSIGNATURE_BOUND = 6900


def _line_bound(c, approval, has_approval):
    approval_bytes = 0
    if has_approval:
        try:
            approval_bytes = len(utf8(canonical_json(approval)))
        except Exception:
            approval_bytes = 0  # not a record at all: its own check refuses it
    return -(-(len(utf8(canonical_json(c))) * 4) // 3) + _STUB_BOUND + approval_bytes + _COUNTERSIGNATURE_BOUND + 64


def check_before(book, proposal, options=None, **named):
    """Ask whether an action the agent is about to take would be outside its slip.

    book: the book so far: the slip and every stub written under it.
    proposal: "slip" (the fingerprint of the slip), "action", and where they
    apply "amount" ({"unit", "value"}), "with" (the id of the service, as the
    slip names it), "details", "approval" (the person's signed approval of
    exactly this action, where the slip asks for one), "terms" (the
    fingerprint of the service's terms for agents, if they are in the book),
    "pass" (for a helper agent: the fingerprint of the pass it acts under),
    "when" (milliseconds since 1970; defaults to now).
    options: the same options as check_book. issuer_keys (the thumbprints of
    the passkeys this check trusts) must be given: a slip signed by any
    other key allows nothing.

    Returns {"allowed", "problems", "breaches", "needs"}. "allowed" is True
    only if the record so far is sound, this device checked every signature
    in it, and the action would be inside the slip. "needs" lists what the
    slip asks to go with the action. A needed approval must be handed over,
    or the action is not allowed. A needed countersignature cannot be known
    beforehand: the action is allowed, and is inside the slip only if the
    other side then countersigns it.
    """
    # The options are read once, through the fixed copy a whole check reads
    # them through, for the book and for the decision alike.
    fixed = fixed_options(options, **named)
    return _decide(lambda: check_book_keeping_state(book, fixed), proposal, fixed)


def check_before_read(read, proposal, options=None):
    """The same check, for a book that has already been read and is carried on
    (the stub writer): nothing is read again. Not part of the public interface."""
    return _decide(read, proposal, options)


def _decide(read, proposal, options):
    answer = {'allowed': False, 'problems': [], 'breaches': [], 'needs': []}
    try:
        if not isinstance(options, Mapping):
            options = {}
        issuer_keys = options.get('issuerKeys')
        if not isinstance(issuer_keys, list) or len(issuer_keys) == 0:
            raise _not_sound('The check before acting must be told which passkeys it trusts. A slip signed by any other key allows nothing.')
        got = read()
        result, state, beside = got['result'], got['state'], got['beside']
        if result['summary']['problemFound']:
            raise _not_sound('A problem was found in the record so far. It must be looked at before the agent acts again.')
        # A record this device could only partly check is not a pass, here either.
        if not result['summary']['fullyChecked']:
            raise _not_sound('This device could not check every signature in the record so far.')
        if not all(e.get('compared') is True for e in result['entries'] if e['kind'] in ('stub', 'pass')):
            raise _not_sound('This device could not compare every stub and every pass in the record so far with its slip.')
        if result['size'] >= MAX_ENTRIES:
            raise Refusal('too-large', 'The book is full: it holds 100,000 entries.')

        f.members(proposal, ['action', 'slip'], ['amount', 'approval', 'details', 'pass', 'terms', 'when', 'with'], 'proposal')
        when_given = proposal.get('when')
        c = {'action': proposal['action'], 'when': format_time(now_ms() if when_given is None else when_given)}
        for name in ('amount', 'details', 'with'):
            if name in proposal:
                c[name] = proposal[name]
        validate_request(c)
        when = f.time(c['when'], 'when')
        if _line_bound(c, proposal.get('approval'), 'approval' in proposal) > MAX_LINE_BYTES:
            raise Refusal('too-large', 'The record of this action would be longer than a line of a book may be.')

        slip = state['slips'].get(proposal['slip']) if isinstance(proposal['slip'], str) else None
        if not slip:
            raise Refusal('slip-missing', 'The slip is not in the book.')
        if not slip['verified']:
            raise _not_sound("This device could not check the slip's signature.")
        # A helper agent acts under a pass, in a chain of its own.
        p = None
        if 'pass' in proposal:
            p = state['passes'].get(proposal['pass']) if isinstance(proposal['pass'], str) else None
            if not p or not p['usable']:
                raise Refusal('pass-missing', 'The pass is not in the book, or did not pass its own check.')
            if p['content']['slip'] != proposal['slip']:
                raise Refusal('pass-mismatch', 'The pass was given under another slip.')
        # The chain allows no stub dated before the one ahead of it.
        if when < (p if p else slip)['lastWhen']:
            raise Refusal('time-went-backwards', 'The action is dated before the last stub in its chain.')

        service = next((s for s in slip['content']['with'] if s['id'] == c['with']), None) if 'with' in c else None
        terms = None
        if 'terms' in proposal:
            t = state['terms'].get(proposal['terms']) if isinstance(proposal['terms'], str) else None
            if not t or not t['usable'] or not t['verified']:
                raise Refusal('terms-not-found', 'The terms are not in the book, or did not pass their check.')
            if not keys_of(service) or canonical_json(service['keys']) != canonical_json(t['content']['by']['keys']):
                raise Refusal('terms-mismatch', 'The terms were not signed with the keys the slip gives for the service named.')
            terms = t['content']

        # Cancelled in the book, or by a cancellation that the person kept and handed over beside it.
        cancelled = slip['cancelled'] is not None or proposal['slip'] in beside
        shown = compare_with_slip(slip['content'], slip['tally'], c, {'service': service, 'terms': terms, 'cancelled': cancelled}, False)
        answer['needs'] = shown['needs']
        breaches = list(shown['breaches'])
        if p:
            # The pass the helper acts under, and every pass above it, as the checker compares them.
            q = p
            while q:
                under = compare_with_slip(pass_as_slip(q['content']), q['tally'], c, {'service': service, 'what': 'pass' if q is p else 'earlier-pass'}, False)
                for b in under['breaches']:
                    if not any(x['code'] == b['code'] for x in breaches):
                        breaches.append(b)
                q = q['parent']
            if p['notAllowed']:
                breaches.append({'code': 'pass-not-allowed', 'message': 'The slip does not allow the pass this action would be taken under.'})

        # The person's approval, checked as the checker will check it.
        if 'approval' in proposal:
            ids = _Ids(state['ids'])
            ids.approvals = set(getattr(state['ids'], 'approvals', ()))
            without = options.get('withoutMethods') if isinstance(options.get('withoutMethods'), list) else []
            approval = check_approval_record(proposal['approval'], c, proposal['slip'], slip, ids, without)
            if approval['state'] != 'valid':
                raise _not_sound("This device could not check the approval's signature.")
            if nan_time(approval['when']) > when + 300 * 1000:
                raise Refusal('approval-dated-after-stub', 'The approval is dated later than the action.')
        elif 'approval' in shown['needs']:
            breaches.append({'code': 'approval-missing', 'message': "The slip asks for the person's own approval of this action, and none was handed to this check."})
        # A countersignature cannot be known beforehand. But where the action
        # names no service, or one for which the slip gives no keys, none can
        # ever be given.
        if 'countersignature' in shown['needs'] and not keys_of(service):
            breaches.append({
                'code': 'countersignature-missing',
                'message': 'The slip asks for the other side to countersign this action, and the action names no service whose keys the slip gives. '
                'No countersignature could be given.',
            })

        answer['breaches'] = breaches
        answer['allowed'] = len(breaches) == 0
    except Exception as e:
        answer['problems'].append(problem_from(e))
    return answer
