# What a stub shows about the agent, compared with its slip.
# Format description, section 8.
#
# The checker and the "check before acting" function both use this one
# comparison, so that nothing is allowed beforehand that would be reported
# afterwards. In one case the check before acting refuses more: see
# _period_with.

from .actions import ACTION_KINDS, CONDUCT_RULES, action_kind
from .encoding import nan_time


def new_tally():
    """The running state kept for one slip while its stubs are read in order."""
    return {'sums': {}, 'counts': {}, 'periods': {}}


def _period_totals(items, period_ms):
    """The total inside the period that ends at each stub. A period is counted
    back from a stub by the times the stubs state, whichever chain a stub is
    in and wherever it stands in the book: an agent and its helpers each have
    a chain, and their stubs need not stand in the book in order of time. So
    the stubs are first put in order of time (those with the same time stay
    in the order of the book), and the period of each takes in the stubs up
    to it that are later than its time minus the period."""
    ordered = sorted(enumerate(items), key=lambda pair: (pair[1]['when'], pair[0]))
    totals = []
    head = 0
    total = 0
    for _, item in ordered:
        total += item['value']
        while ordered[head][1]['when'] <= item['when'] - period_ms:
            total -= ordered[head][1]['value']
            head += 1
        totals.append((item, total))
    return totals


def _period_with(items, when, period_ms, value):
    """For a check before acting: the largest total of any period that the
    proposed action would fall in. That is its own period, and the period of
    every stub dated after it and less than one period later.

    Where a stub dated after the proposed action is already over the limit,
    the action is refused: it would add to a period that holds too much. A
    checker, with the stub written, reports nothing new, because the finding
    stands with the later stub, which it already marks. This is the one case
    where the check before acting refuses more than a checker would report."""
    proposed = {'when': when, 'value': value}
    worst = 0
    for item, total in _period_totals([*items, proposed], period_ms):
        if (item is proposed or (item['when'] > when and item['when'] < when + period_ms)) and total > worst:
            worst = total
    return worst


def period_words(seconds):
    if seconds % 86400 == 0:
        return 'any 24 hours' if seconds == 86400 else f'any {seconds // 86400} days'
    if seconds % 3600 == 0:
        return 'any hour' if seconds == 3600 else f'any {seconds // 3600} hours'
    return f'any {seconds} seconds'


def _allowed_in(limit):
    return int(limit['count'] if 'count' in limit else limit['max'])


def _over_period(limit, total, W, proposed=False):
    """proposed: an action that is only proposed (a check before acting), of
    which no stub exists yet."""
    With, are, is_ = ('With this action', 'there would be', 'would be') if proposed else ('With this stub', 'there are', 'is')
    if 'count' in limit:
        message = f"{With} {are} {total} such actions in {period_words(limit['per'])}. {W} allows {limit['count']}."
    else:
        message = f"{With} the total in {period_words(limit['per'])} {is_} {total} {limit['unit']}. {W}'s limit is {limit['max']} {limit['unit']}."
    return {'code': 'over-period-limit', 'message': message}


def _words_for(what):
    """The words for what a stub is compared with: a slip, the pass a helper
    acts under, or a pass further up, from which that pass was handed on."""
    if what == 'pass':
        return 'The pass', 'the pass'
    if what == 'earlier-pass':
        return 'The earlier pass', 'the earlier pass'
    return 'The slip', 'the slip'


def settle_periods(s, tally, late):
    """Once every stub under a slip, or under a pass, has been read: settle its
    limits "in any period". Each stub whose period holds more than the limit
    allows is given the finding. It can be done only at the end, because a
    stub further on in the book may be dated earlier (see _period_totals).

    The findings are not put into the stubs' own lists, which stay as they
    are: they are gathered in "late" (an IdentityMap), each list under the
    stub's own list. So the same stubs can be settled again after more have
    been read."""

    def over(b):
        return b['code'] == 'over-period-limit'

    for i, items in tally['periods'].items():
        limit = s['limits'][i]
        allowed = _allowed_in(limit)
        for item, total in _period_totals(items, limit['per'] * 1000):
            if not (total > allowed):
                continue
            found = late.get(item['late'])
            if found is None:
                found = []
                late.set(item['late'], found)
            # A pass does not repeat a finding that the slip, or a pass before it, gave for the stub.
            if item['what'] != 'slip' and (any(over(b) for b in item['late']) or any(over(b) for b in found)):
                continue
            found.append(_over_period(limit, total, item['W']))


def limit_words(limit):
    """Describe a limit in words, for people."""
    period = f" in {period_words(limit['per'])}" if 'per' in limit else ' in total'
    if 'each' in limit:
        return f"{limit['action']}: no single action above {limit['each']} {limit['unit']}"
    if 'count' in limit:
        return f"{limit['action']}: no more than {limit['count']} {'action' if limit['count'] == 1 else 'actions'}{period}"
    return f"{limit['action']}: no more than {limit['max']} {limit['unit']}{period}"


def condition_words(r):
    """Describe a condition ("requires") in words, for people."""
    what = "needs the person's own approval" if r['need'] == 'approval' else "needs the other side's countersignature"
    above = f" above {r['above']} {r['unit']}" if 'above' in r else ''
    return f"{r['action'] if 'action' in r else 'every action'}: {what}{above}"


def never_words(name):
    """Describe one name of a "never" list in words, for people."""
    if name in CONDUCT_RULES:
        return CONDUCT_RULES[name]
    text = ACTION_KINDS[name]
    return f'Never do an action of the kind "{name}": {text[:1].lower()}{text[1:]}'


def compare_with_slip(s, tally, c, facts, commit=True):
    """Compare one stub, or one action that is only proposed, with its slip.

    s: the slip's content. tally: the slip's running state, or None when only
    single pages are at hand. c: the stub's content: "action", "when", and
    where present "amount" and "with". facts: "service" (the service in the
    slip that the stub names, if it names one the slip knows), "terms" (the
    content of the service's terms the stub relies on, if any), "cancelled"
    (whether the slip was cancelled earlier in the book), "what" ('slip',
    'pass' or 'earlier-pass'), "late" (where a finding that can be made only
    once every stub has been read is to be put; see settle_periods). commit:
    False to leave the running state as it was (a check before acting).

    Returns {"breaches", "needs", "running"}; "needs" lists what the slip asks
    to go with this action: "countersignature", "approval".
    """
    # The same comparison is made with a pass: the messages then say so.
    W, w = _words_for(facts.get('what'))
    breaches = []
    when = nan_time(c['when'])

    # A limit "in any period". While a book is read, the stub is only noted,
    # and the limit is settled once every stub has been read (settle_periods).
    # A check before acting works it out at once, for the proposed action.
    def in_period(i, limit, value):
        items = tally['periods'].get(i, [])
        if commit:
            tally['periods'][i] = items
            items.append({'when': when, 'value': value, 'W': W, 'what': facts.get('what') or 'slip', 'late': facts.get('late') if facts.get('late') is not None else breaches})
            return
        worst = _period_with(items, when, limit['per'] * 1000, value)
        if worst > _allowed_in(limit):
            breaches.append(_over_period(limit, worst, W, True))

    if c['action'] not in s['actions']:
        breaches.append({'code': 'action-not-allowed', 'message': f'{W} does not allow the action "{c["action"]}".'})
    kind = action_kind(c['action'])
    if facts.get('cancelled'):
        breaches.append({'code': 'after-cancellation', 'message': 'The person cancelled the slip before this action.'})
    if kind and kind in s['never']:
        breaches.append({'code': 'prohibited', 'message': f'{W} says the agent must never do an action of the kind "{kind}", and "{c["action"]}" is of that kind.'})
    if 'with' in c and not facts.get('service'):
        breaches.append({'code': 'party-not-allowed', 'message': f'{W} does not name "{c["with"]}" as someone the agent may deal with.'})
    if when < nan_time(s['validFrom']) or when >= nan_time(s['validUntil']):
        breaches.append({'code': 'outside-valid-time', 'message': f'The action is dated outside the time {w} allows.'})
    if facts.get('terms'):
        t = facts['terms']
        if c['action'] not in t['accepts']:
            breaches.append({'code': 'outside-terms', 'message': f'The service\'s terms for agents do not accept the action "{c["action"]}".'})
        elif when < nan_time(t['validFrom']) or when >= nan_time(t['validUntil']):
            breaches.append({'code': 'outside-terms', 'message': "The action is dated outside the time the service's terms for agents were in force."})

    # Amounts. Every amount limit for one action is in one unit (the slip's
    # check makes sure of it), so a stub is asked for its amount once.
    missing = False

    def amount_in(unit):
        nonlocal missing
        if c.get('amount') and c['amount']['unit'] == unit:
            return True
        if not missing:
            breaches.append({'code': 'amount-missing', 'message': f'{W} sets a limit or a condition in "{unit}" for this action, and the stub gives no amount in that unit.'})
            missing = True
        return False

    running = None
    for i, limit in enumerate(s['limits']):
        if limit['action'] != c['action']:
            continue
        period_ms = limit['per'] * 1000 if 'per' in limit else None
        if 'count' in limit:
            if tally is None:
                continue  # a single page cannot show a count
            if period_ms is None:
                n = tally['counts'].get(i, 0) + 1
                if commit:
                    tally['counts'][i] = n
                if n > limit['count']:
                    breaches.append({'code': 'over-count-limit', 'message': f"{'This is' if commit else 'This would be'} action number {n} of this kind under {w}. {W} allows {limit['count']}."})
            else:
                in_period(i, limit, 1)
            continue
        if not amount_in(limit['unit']):
            continue
        value = int(c['amount']['value'])
        if 'each' in limit:
            if value > int(limit['each']):
                breaches.append({'code': 'over-each-limit', 'message': f"This action is {value} {limit['unit']}. {W} allows no single action above {limit['each']} {limit['unit']}."})
        elif period_ms is None:
            if tally is not None:
                total = tally['sums'].get(i, 0) + value
                if commit:
                    tally['sums'][i] = total
                running = {'action': c['action'], 'unit': limit['unit'], 'total': str(total), 'max': limit['max']}
                if total > int(limit['max']):
                    breaches.append({
                        'code': 'over-limit',
                        'message': f"{'With this stub the total is' if commit else 'With this action the total would be'} {total} {limit['unit']}. {W}'s limit is {limit['max']} {limit['unit']}: over by {total - int(limit['max'])}.",
                    })
            elif value > int(limit['max']):
                # A single page cannot show a running total, but it can show a stub
                # that passes the limit all by itself.
                breaches.append({'code': 'over-limit', 'message': f"This stub alone is {value} {limit['unit']}. {W}'s limit is {limit['max']} {limit['unit']} in total."})
        elif tally is not None:
            in_period(i, limit, value)
        elif value > int(limit['max']):
            breaches.append({'code': 'over-period-limit', 'message': f"This stub alone is {value} {limit['unit']}. {W}'s limit is {limit['max']} {limit['unit']} in {period_words(limit['per'])}."})

    # What the slip asks to go with this action.
    needs = []
    for r in s['requires']:
        if 'action' in r and r['action'] != c['action']:
            continue
        if 'above' in r:
            if not amount_in(r['unit']):
                continue
            if not (c['amount']['value'] > r['above']):
                continue
        if r['need'] not in needs:
            needs.append(r['need'])

    return {'breaches': breaches, 'needs': needs, 'running': running}
