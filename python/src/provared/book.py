# The book (a list of entries, one to a line), the chain, what a stub shows
# about the agent, the top fingerprint and the Show.
# Format description, sections 7 to 11 and 17 to 19.
#
# The checker keeps three questions apart:
#   - was a problem found in the record?          (problems)
#   - was every signature checked on this device? (fullyChecked)
#   - did the agent stay in its slip?             (breaches)
# A breach is not a fault in the record. It is what a sound record shows.
# "Intact" is said only when no problem was found and every signature was
# checked.

import copy
import re
from collections.abc import Mapping

from . import _js
from . import fields as f
from .approval import request_of, validate_approval_content
from .blockstamp import check_block_stamp
from .compare import compare_with_slip, new_tally, settle_periods
from .encoding import Refusal, canonical_json, format_time, from_base64url, nan_time, parse_canonical, problem_from, to_base64url, utf8
from .jws import parse_record, signing_input
from .pass_ import MAX_PASSES, validate_pass_content
from .seal import CLOCK_ALLOWANCE_MS, decode_stamps, key_set_fingerprint, validate_seal_content
from .service import validate_refusal_content, validate_terms_content
from .signatures import verify_signature
from .slip import _UNDEFINED, check_passkey_signature, check_slip
from .standing import validate_acknowledgement_content, validate_cancellation_content, validate_vouching_content, validate_withdrawal_content
from .stub import validate_countersignature_content, validate_stub_content
from .timestamp import check_stamp
from .tree import inclusion_path, tree_builder, tree_root, verify_inclusion

INF = float('inf')
NAN = float('nan')

MAX_ENTRIES = 100000
"""The most entries a book may hold."""
MAX_LINE_BYTES = 131072
"""The longest line of a book, in bytes."""
MAX_PAGES = 64
"""The most pages a Show may hold."""
MAX_HELD = 16
"""The most cancellations that may be handed over beside a book."""
MAX_ACKNOWLEDGEMENTS = 4
"""The most acknowledgements that may be handed over with one cancellation."""

# What can be said about time, with and without an outside time-stamp.
_NOT_STAMPED = (
    'Nothing here is time-stamped by an outside service that you named as trusted. So it does not show when the record was made, '
    'and the latest stubs under a slip or a pass, or a slip or a pass with all its stubs, could have been removed.'
)


def _block_words(sealed):
    return (
        f"A block of a public blockchain, which you trust to be part of the chain, covers the first {sealed['entries']} entries: they existed by {sealed['when']}, "
        'taking the time the block states as right to within two hours. What came after is not time-stamped, and a later seal with everything after it could '
        'have been removed: compare the top fingerprint and the number of entries with a copy you trust. A block time-stamp rests on SHA-256 and on the block '
        'being part of the chain, not on a signature.'
    )


def _stamped_words(sealed):
    if sealed['by'] == 'block':
        return _block_words(sealed)
    return (
        f"An outside time-stamp covers the first {sealed['entries']} entries: they existed by {sealed['when']}, as the time-stamp service states. What came "
        'after is not time-stamped, and a later seal with everything after it could have been removed: compare the top fingerprint and the number of entries '
        "with a copy you trust. Time-stamp services sign with methods of today's kind, which are not quantum-safe."
    )


LIMITS = [
    'It shows what was recorded, not what was left out. An agent that acts and writes no stub leaves no trace here.',
    "A one-sided stub shows what the agent's side said, not what the other side did.",
    "A refusal shows what the service's side said, not what the agent did.",
    'It does not show that an action was wise, lawful or wanted.',
    'A rule of conduct in a slip, such as "never claim to be a human being", is the person\'s signed instruction. No check can show that the agent kept it.',
    'It does not show who was holding the device when the passkey signed.',
    'A name in a record is a label. Only keys are checked.',
    _NOT_STAMPED,
]
"""What no check of a draft version 0 record can show. Stated with every result."""


def entry_line(entry):
    """Write one entry of a book as its line (without the line feed)."""
    return canonical_json(entry)


def write_book(entries):
    """Write a book from its entries."""
    return ''.join(entry_line(e) + '\n' for e in entries)


def _split_lines(text):
    """Split a book into its lines, stopping as soon as there are too many, so
    that a flood of line feeds costs nothing. A missing line feed after the
    last line is allowed."""
    lines = []
    at = 0
    n = len(text)
    while at < n:
        if len(lines) >= MAX_ENTRIES:
            raise Refusal('too-large', 'The book holds more than 100,000 entries.')
        feed = text.find('\n', at)
        end = n if feed == -1 else feed
        lines.append(text[at:end])
        at = end + 1
    return lines


def _check_key_set_signatures(parsed, keys, without):
    """Check the signatures of a record against a key set, in order."""
    states = []
    for i, s in enumerate(parsed.signatures):
        state = verify_signature(keys[i], s['signature'], signing_input(s['protected_b64'], parsed.payload_b64), without)
        states.append({'method': keys[i]['alg'], 'state': state})
    return states


def _overall(states):
    if any(s['state'] == 'invalid' for s in states):
        return 'invalid'
    if any(s['state'] == 'unavailable' for s in states):
        return 'unavailable'
    return 'valid'


def _verified_by(states):
    """How much of an entry's own signing was confirmed on this device: "all",
    "some" (one of two signatures; the other method is not built in) or "none"."""
    if len(states) == 0 or any(s['state'] == 'invalid' for s in states):
        return 'none'
    valid = sum(1 for s in states if s['state'] == 'valid')
    return 'all' if valid == len(states) else 'some' if valid > 0 else 'none'


class _Entry(dict):
    """An entry of an answer. It also keeps, out of sight, the time of the first
    counted time-stamp that covers it."""

    __slots__ = ('stamped',)


def _new_entry(index, kind='unreadable'):
    e = _Entry(index=index, kind=kind, fingerprint=None, verified='none', problems=[], breaches=[], notes=[])
    e.stamped = None
    return e


class _Ids(set):
    """The unique numbers so far, and the ids of the approvals used so far:
    one approval is one action."""

    __slots__ = ('approvals',)


class _Vouchings(dict):
    """The vouching records so far, by fingerprint; and by whom they vouch for
    ("index"), so that looking one up does not mean reading them all."""

    __slots__ = ('index',)


class _Reader:
    """What a reader keeps while it reads the entries of a book, one line at a
    time. Everything worked out from the lines so far is here, so that one
    more line can be read without reading the others again.

    In "whole" mode the lines are a whole book: the chain and the running
    totals are checked. Otherwise they are single pages out of a book, and
    only what one page can show is checked."""

    def __init__(self, options, whole):
        self.options = options
        self.whole = whole
        # Whether this reader was split off another one to try one more stub, and reads nothing else (_fork_reader).
        self.forked = False
        self.entries = []
        self.slips = {}
        self.terms = {}
        self.ids = _Ids()
        self.ids.approvals = set()
        # The passes so far, by fingerprint: permissions handed on to helper agents.
        self.passes = {}
        self.vouchings = _Vouchings()
        self.vouchings.index = {}
        # The seals so far: the last one, how far an outside time-stamp reaches,
        # and the tree as it grows, so that each seal can be compared with the
        # entries before it.
        self.seals = {'count': 0, 'last': None, 'lastWhen': -INF, 'lastStampTime': -INF, 'latest': -INF, 'next': 0, 'sealed': None}
        self.tree = tree_builder() if whole else None
        # Problems with what was handed over beside the record (disclosures), which are not faults of an entry.
        self.handed_problems = []


def _without(options):
    value = options.get('withoutMethods')
    return value if isinstance(value, list) else []


def _read_line(reader, index, line, disclosures=_UNDEFINED):
    """Read one more line: check it against everything read before it, and
    keep what later lines will need."""
    options = reader.options
    whole = reader.whole
    entries = reader.entries
    seals = reader.seals
    without = _without(options)
    entry = _new_entry(index)
    entries.append(entry)
    try:
        # A character is at least one byte, so the first test needs no encoding.
        if _js.utf16_length(line) > MAX_LINE_BYTES or len(utf8(line)) > MAX_LINE_BYTES:
            raise Refusal('too-large', 'The line is longer than 131,072 bytes.')
        # Three common slips get words of their own; the codes are those any
        # other such line gets.
        if line == '':
            raise Refusal('not-json', 'The line is empty. A book holds no empty lines, and ends with a single line feed.')
        if line.startswith('﻿'):
            raise Refusal('not-json', 'The line starts with a byte-order mark, which a book may not hold. Save the file as UTF-8 without one.')
        if line.endswith('\r'):
            raise Refusal('line-not-canonical', 'The line ends with a carriage return. A line of a book ends with a line feed alone, with no carriage return before it.')
        value = parse_canonical(line, 'line-not-canonical')
        names = ','.join(_js.sort_strings(value.keys())) if isinstance(value, dict) else ''
        # A reader split off to try one more stub reads nothing else: a stub
        # is the one kind of entry that changes nothing read before it.
        if reader.forked and names not in _STUB_ENTRIES:
            raise RuntimeError('only a stub may be tried')
        if names == 'slip':
            entry['kind'] = 'slip'
            check = check_slip(value.get('slip'), options, disclosures)
            # (Disclosures on a page of a Show and disclosures handed over beside it are used together: see check_slip.)
            for p in check['disclosureProblems']:
                reader.handed_problems.append({
                    'code': p['code'],
                    'message': f"The disclosures handed over for the slip at entry {index} did not pass their check, so they were not used: the slip was checked with those fields covered. {p['message']}",
                })
            entry.update({
                'covered': check['covered'],
                'fingerprint': check['fingerprint'],
                'problems': check['problems'],
                'notes': check['notes'],
                'signature': check['signature'],
                'issuerKey': check['issuerKey'],
                'content': check['content'],
            })
            ids = reader.ids
            if check['content']:
                if check['content']['id'] in ids:
                    entry['problems'].append({'code': 'duplicate-id', 'message': 'Another record has the same unique number.'})
                ids.add(check['content']['id'])
            if check['fingerprint']:
                if check['fingerprint'] in reader.slips:
                    entry['problems'].append({'code': 'duplicate-slip', 'message': 'This slip is already in the book.'})
                else:
                    reader.slips[check['fingerprint']] = {
                        'content': check['content'],
                        'usable': len(entry['problems']) == 0,
                        'verified': len(entry['problems']) == 0 and check['signature']['state'] == 'valid',
                        'next': 0,
                        'last': None,
                        'lastWhen': -INF,
                        'tally': new_tally(),
                        # The stubs compared so far, and the cancellation, if there is one.
                        'stubs': [],
                        'cancelled': None,
                    }
            entry['verified'] = 'all' if check['signature']['state'] == 'valid' else 'none'
            # Who vouches for the names in the slip, if anyone does.
            if check['content']:
                s = check['content']
                # A vouching record must be in force for the whole of the slip's time.
                span = (nan_time(s['validFrom']), nan_time(s['validUntil']))
                vouchings = reader.vouchings
                entry['vouched'] = {
                    'issuer': _vouch_for(vouchings, 'person', s['issuer']['key'], s['issuer'].get('name'), span),
                    'agent': _vouch_for(vouchings, 'agent', s['agent']['keys'], s['agent'].get('name'), span),
                    # Every service has a place here, so that looking one up by its id finds only what was put there.
                    'services': _js.in_key_order({
                        w['id']: _vouch_for(vouchings, 'service', w['keys'], w.get('name'), span) if keys_of(w) else None for w in s['with']
                    }),
                }
                # A name that an organisation the checker trusts vouches for is no longer only a label.
                if entry['vouched']['issuer'] and entry['vouched']['issuer']['counted']:
                    entry['notes'] = [n for n in entry['notes'] if not n.startswith("The issuer's key was not compared")]
        elif names in _STUB_ENTRIES:
            entry['kind'] = 'stub'
            _check_stub_entry(entry, value, reader.slips, reader.terms, reader.passes, reader.ids, without, whole)
        elif names == 'refusal':
            entry['kind'] = 'refusal'
            _check_refusal_entry(entry, value, reader.slips, reader.ids, without, whole)
        elif names == 'terms':
            entry['kind'] = 'terms'
            _check_terms_entry(entry, value, reader.terms, reader.ids, without)
        elif names in ('seal', 'seal,stamps'):
            entry['kind'] = 'seal'
            # The top fingerprint of the entries before it is worked out only once the seal has been read.
            before = (lambda: {'size': index, 'root': to_base64url(reader.tree.root())}) if whole else None
            _check_seal_entry(entry, value, seals, reader.ids, options, before, entries, not whole)
            if entry.get('content'):
                # In force at the time the seal states and, where a counted time-stamp says when the seal existed, then too.
                times = [nan_time(entry['content']['when'])]
                if entry.get('stampedAt'):
                    times.append(nan_time(entry['stampedAt']))
                by = entry['content']['by']
                entry['vouched'] = _vouch_for(reader.vouchings, 'recorder', by['keys'], by.get('name'), (_js_min(times), _js_max(times) + 1))
                if entry['vouched'] and entry['vouched']['counted']:
                    entry['notes'] = [n for n in entry['notes'] if not n.startswith('The keys that signed this seal were not compared')]
        elif names in ('cancellation', 'cancellation,stamps'):
            entry['kind'] = 'cancellation'
            _check_cancellation_entry(entry, value, reader.slips, reader.ids, options, whole)
        elif names == 'acknowledgement':
            entry['kind'] = 'acknowledgement'
            _check_acknowledgement_entry(entry, value, reader.slips, reader.passes, reader.ids, entries, without, whole)
        elif names == 'pass':
            entry['kind'] = 'pass'
            _check_pass_entry(entry, value, reader.slips, reader.passes, reader.ids, without, whole)
            if entry.get('content'):
                c = entry['content']
                entry['vouched'] = _vouch_for(reader.vouchings, 'agent', c['to']['keys'], c['to'].get('name'), (nan_time(c['validFrom']), nan_time(c['validUntil'])))
        elif names == 'vouching':
            entry['kind'] = 'vouching'
            _check_vouching_entry(entry, value, reader.vouchings, reader.ids, options)
        elif names == 'withdrawal':
            entry['kind'] = 'withdrawal'
            _check_withdrawal_entry(entry, value, reader.vouchings, reader.ids, options, whole)
        else:
            raise Refusal('unknown-entry', 'The line is not one of the known kinds of entry.')
        # Only a slip may hold covered fields: disclosures handed over with any other page belong to nothing.
        if disclosures is not _UNDEFINED and entry['kind'] != 'slip':
            entry['problems'].append({'code': 'cover-invalid', 'message': 'Disclosures were handed over with a page that is not a slip. Only a slip may hold covered fields.'})
    except Exception as e:
        entry['problems'].append(problem_from(e))
    if entry['problems']:
        entry['verified'] = 'none'
    # The latest time that a sound entry so far states: a seal cannot be dated before it.
    elif entry['verified'] != 'none' and _when_of(entry) > seals['latest']:
        seals['latest'] = _when_of(entry)
    if reader.tree is not None:
        reader.tree.add(utf8(line))


def _js_min(values):
    """Math.min: NaN if any value is NaN; Infinity for none."""
    result = INF
    for v in values:
        if v != v:
            return NAN
        if v < result:
            result = v
    return result


def _js_max(values):
    """Math.max: NaN if any value is NaN; -Infinity for none."""
    result = -INF
    for v in values:
        if v != v:
            return NAN
        if v > result:
            result = v
    return result


def _settle_late(reader):
    """The findings that can be made only once every stub so far has been read:
    the limits "in any period" (a stub further on in the book, in another
    chain, may be dated earlier), and what a cancellation handed over beside
    the book shows (_check_held). They are worked out afresh for each answer
    and kept apart from the entries, each list under its entry's own list of
    findings, so that a book can be carried on after an answer was given."""
    late = _js.IdentityMap()
    # The slips first, then the passes from the last in the book to the
    # first, which is from the pass nearest a stub upwards: a finding
    # already given for a stub is not given again (compare.py).
    for slip in reader.slips.values():
        if slip['content']:
            settle_periods(slip['content'], slip['tally'], late)
    for p in reversed(list(reader.passes.values())):
        settle_periods(pass_as_slip(p['content']), p['tally'], late)
    return late


def _answered(entry, late, entries):
    """An entry as an answer gives it: with the findings that were worked out
    last, and with no time of its own if it did not pass its check. The
    entry the reader keeps is left as it is."""
    more = late.get(entry['breaches'])
    out = dict(entry)
    if more:
        out['breaches'] = [*entry['breaches'], *more]
    # A cancellation that passed when its acknowledgement was read may have
    # failed since: a later seal's time-stamp can show that it is not dated
    # as it says. The acknowledgement then names a cancellation that did not
    # pass its check.
    if entry['kind'] == 'acknowledgement' and 'cancellation' in entry and entries[entry['cancellation']]['problems']:
        _fail_acknowledgement(out)
    if out['problems']:
        out.pop('stampedAt', None)
    return out


def _fail_acknowledgement(entry):
    entry['problems'] = [*entry['problems'], {'code': 'cancellation-not-found', 'message': 'The cancellation this acknowledgement names did not pass its own check.'}]
    entry['verified'] = 'none'
    entry.pop('cancellation', None)


def _fork_reader(reader, whole=False):
    """A reader that carries on by itself from where this one stands, to try
    one more line. The reader it was split from is left exactly as it was,
    whatever becomes of this one.

    To try a stub, what a stub changes is copied (its chain, the running
    totals, the unique numbers, the tree); the entries read so far, the
    terms and the vouching records are shared, because a stub changes none
    of them, and such a reader refuses any other kind of line.

    To try a line of any kind ("whole"), the entries are copied as well,
    with the lists inside them that a later line may add to (a seal's
    time-stamp marks the entries before it; a cancellation marks stubs),
    and so are the terms and the vouching records. Whatever points at an
    entry, or at its list of findings, is pointed at the copy."""
    twin_entry = _js.IdentityMap()
    twin_list = _js.IdentityMap()
    if whole:
        entries = []
        for e in reader.entries:
            c = _Entry(e)
            c['problems'] = list(e['problems'])
            c['breaches'] = list(e['breaches'])
            c['notes'] = list(e['notes'])
            c.stamped = getattr(e, 'stamped', None)
            twin_entry.set(e, c)
            twin_list.set(e['breaches'], c['breaches'])
            entries.append(c)
    else:
        entries = list(reader.entries)

    def copy_tally(t):
        periods = {}
        for i, items in t['periods'].items():
            if whole:
                periods[i] = [{**item, 'late': twin_list.get(item['late'], item['late'])} for item in items]
            else:
                periods[i] = list(items)
        return {'sums': dict(t['sums']), 'counts': dict(t['counts']), 'periods': periods}

    slips = {}
    for fp, s in reader.slips.items():
        slips[fp] = {
            **s,
            'tally': copy_tally(s['tally']),
            'stubs': [twin_entry.get(e, e) for e in s['stubs']] if whole else list(s['stubs']),
            'cancelled': None if s['cancelled'] is None else dict(s['cancelled']),
        }
    # The vouching records can be withdrawn by a later line: they are copied, and found again by the copies.
    terms, vouchings = reader.terms, reader.vouchings
    if whole:
        terms = dict(reader.terms)
        twin_vouching = _js.IdentityMap()
        vouchings = _Vouchings()
        for fp, v in reader.vouchings.items():
            c = dict(v)
            twin_vouching.set(v, c)
            vouchings[fp] = c
        vouchings.index = {}
        for key, found in reader.vouchings.index.items():
            vouchings.index[key] = {
                'counted': [twin_vouching.get(v, v) for v in found['counted']],
                'other': [twin_vouching.get(v, v) for v in found['other']],
            }
    # A pass points to the pass it was handed on from, which is earlier in the book: the copies point to the copies.
    passes = {}
    twins = _js.IdentityMap()
    for fp, p in reader.passes.items():
        c = {**p, 'parent': twins.get(p['parent']) if p['parent'] else None, 'tally': copy_tally(p['tally'])}
        twins.set(p, c)
        passes[fp] = c
    ids = _Ids(reader.ids)
    ids.approvals = set(reader.ids.approvals)
    out = _Reader.__new__(_Reader)
    out.options = reader.options
    out.whole = reader.whole
    out.forked = not whole
    out.entries = entries
    out.slips = slips
    out.terms = terms
    out.passes = passes
    out.ids = ids
    out.vouchings = vouchings
    out.seals = dict(reader.seals)
    out.tree = reader.tree.fork()
    out.handed_problems = list(reader.handed_problems)
    return out


# --- the options a checker reads ---

OPTION_NAMES = ['issuerKeys', 'sealKeys', 'stampServices', 'blocks', 'vouchers', 'disclosures', 'cancellations', 'expectedRoot', 'expectedSize', 'withoutMethods']

# The same options, as a Python caller may name them.
_SNAKE = {
    'issuer_keys': 'issuerKeys',
    'seal_keys': 'sealKeys',
    'stamp_services': 'stampServices',
    'blocks': 'blocks',
    'vouchers': 'vouchers',
    'disclosures': 'disclosures',
    'cancellations': 'cancellations',
    'expected_root': 'expectedRoot',
    'expected_size': 'expectedSize',
    'without_methods': 'withoutMethods',
}


class _Fixed(dict):
    """The options of a check, fixed. "unreadable" names any that nest too deeply to be read."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.unreadable = []


class _Unreadable:
    """What stands, in a fixed copy of the options, for a value more than 16
    levels down. In the JavaScript library such a value cannot be read: a
    check that reads it fails there, and the stub writer refuses it as not
    plain data. Here it stands as a value of no kind a check accepts, so a
    check that reads it refuses it there, and the stub writer refuses it as
    anything that is not plain data. No option nests so deep."""

    __slots__ = ()

    def __repr__(self):
        return '<a value more than 16 levels down, which cannot be read>'


_UNREADABLE = _Unreadable()


def _plain(value, memo=None, depth=0, deep=None):
    """A deep copy of an option, with tuples as lists, as JSON would hold it.
    A value met twice is copied once, so that the copy holds the same
    sharing, and costs no more to make than what was handed over holds."""
    if not isinstance(value, (dict, list, tuple)) and not isinstance(value, Mapping):
        return copy.deepcopy(value)
    if depth > 16:
        if deep is not None:
            deep.append(True)
        return _UNREADABLE
    if memo is None:
        memo = {}
    found = memo.get(id(value))
    if found is not None:
        return found[1]
    if isinstance(value, (list, tuple)):
        made = [_plain(v, memo, depth + 1, deep) for v in value]
    else:
        made = {k: _plain(v, memo, depth + 1, deep) for k, v in value.items()}
    memo[id(value)] = (value, made)
    return made


def fixed_options(options=None, **named):
    """The options of a check, fixed: read once and copied, so that nothing done
    afterwards to what was handed over changes a check that is carried on.
    The options are named as in the JavaScript library ("issuerKeys"), or
    as keyword arguments in Python's way ("issuer_keys"). A fixed copy handed
    in again is used as it is. Not part of the public interface."""
    if isinstance(options, _Fixed) and not named:
        return options
    fixed = _Fixed()
    if isinstance(options, Mapping):
        for name in OPTION_NAMES:
            if name in options:
                deep = []
                fixed[name] = _plain(options[name], deep=deep)
                if deep:
                    # No option nests so deep. The check that reads it fails.
                    fixed.unreadable.append(name)
    for name, value in named.items():
        if name not in _SNAKE:
            raise TypeError(f'unknown option "{name}"')
        if value is not None:
            deep = []
            fixed[_SNAKE[name]] = _plain(value, deep=deep)
            if deep:
                fixed.unreadable.append(_SNAKE[name])
    return fixed


_MAX_UNCOUNTED = 8
"""The most vouching records from organisations the checker did not name that are kept for one name and key."""


def keys_of(service):
    """The keys a slip gives for a service, if it gives any."""
    return service['keys'] if isinstance(service, dict) and 'keys' in service else None


def _vouched_key(kind, key, name):
    """What a vouching record is found by: the kind, the key or keys, and the name, exactly."""
    return canonical_json([kind, key, name])


def _vouch_for(vouchings, kind, key, name, span):
    """Who vouches for a name: the vouching record earlier in the book, still
    standing, that names exactly this key (or these keys) and exactly this
    name, and was in force for the whole of the time given. One from an
    organisation the checker named as trusted is preferred, and only that
    one counts. A covered name is not text, and nobody vouches for it."""
    if not isinstance(name, str):
        return None
    found = vouchings.index.get(_vouched_key(kind, key, name))
    if not found:
        return None

    def standing(v):
        return not v['withdrawn'] and span[0] >= nan_time(v['content']['validFrom']) and span[1] <= nan_time(v['content']['validUntil'])

    v = next((v for v in found['counted'] if standing(v)), None) or next((v for v in found['other'] if standing(v)), None)
    return {'counted': v['counted'], 'by': v['content']['by']['name'], 'keys': v['signer']} if v else None


def _find_pass(passes, fp, slip_fingerprint, whole):
    """The pass a stub or a further pass relies on."""
    p = passes.get(fp)
    if not p or not p['usable']:
        raise Refusal(
            'pass-missing',
            'The pass this entry relies on is not earlier in the book, or did not pass its own check.'
            if whole
            else 'The pass this entry relies on is not among the pages, or did not pass its own check.',
        )
    if p['content']['slip'] != slip_fingerprint:
        raise Refusal('pass-mismatch', 'The pass this entry relies on was given under another slip.')
    return p


def pass_as_slip(p):
    """A pass seen as a slip, so that the same comparison can be made with it."""
    return {'actions': p['actions'], 'limits': p['limits'], 'requires': [], 'never': [], 'validFrom': p['validFrom'], 'validUntil': p['validUntil']}


def _check_pass_entry(entry, value, slips, passes, ids, without, whole):
    """A pass: an agent hands part of its permission to a helper agent."""
    entry['signatures'] = []
    # Whether this pass was compared with what its writer holds. It is not,
    # if the pass or the slip could not be confirmed.
    entry['compared'] = False
    parsed = parse_record(value.get('pass'), 'pass')
    entry['fingerprint'] = parsed.fingerprint
    validate_pass_content(parsed.content)
    c = parsed.content
    entry['content'] = c
    entry['slip'] = c['slip']
    _note_id(entry, ids, c['id'])
    slip = _find_slip(slips, c['slip'], whole)
    # Who may pass on: the slip's own agent, or the helper named in the pass before.
    parent = _find_pass(passes, c['from'], c['slip'], whole) if 'from' in c else None
    entry['signatures'] = _check_key_set_signatures(parsed, parent['content']['to']['keys'] if parent else slip['content']['agent']['keys'], without)
    if _overall(entry['signatures']) == 'invalid':
        entry['problems'].append({'code': 'signature-invalid', 'message': 'A signature on the pass does not fit the keys of the agent that passes on.'})
    entry['verified'] = _verified_by(entry['signatures'])
    _under_confirmed_slip(entry, slip)
    level = parent['level'] + 1 if parent else 1
    # No slip can allow a permission to be passed on more than ten times in
    # a row. A pass further down is refused, so that every stub can be
    # compared with every pass above its own.
    if level > MAX_PASSES:
        entry['problems'].append({'code': 'pass-too-deep', 'message': 'A permission may be passed on at most ten times in a row, and this pass is one more.'})
    allowed = slip['content']['passes'] if 'passes' in slip['content'] else 0
    not_allowed = parent['notAllowed'] if parent else False

    # What the pass shows about the agent that passed on.
    if not entry['problems'] and entry['verified'] != 'none' and slip['verified']:
        entry['compared'] = True
        held = parent['content'] if parent else slip['content']
        if level > allowed:
            not_allowed = True
            if allowed == 0:
                message = 'The slip does not allow its permission to be passed on.'
            else:
                times = 'once' if allowed == 1 else f'{allowed} times'
                message = f'The slip allows its permission to be passed on {times}, and this is one more.'
            entry['breaches'].append({'code': 'pass-not-allowed', 'message': message})
        if (
            any(action not in held['actions'] for action in c['actions'])
            or nan_time(c['validFrom']) < nan_time(held['validFrom'])
            or nan_time(c['validUntil']) > nan_time(held['validUntil'])
        ):
            entry['breaches'].append({'code': 'pass-wider', 'message': 'The pass hands on more than the agent that wrote it holds: an action, or a time, outside its own permission.'})
        when = nan_time(c['when'])
        if when < nan_time(held['validFrom']) or when >= nan_time(held['validUntil']):
            entry['breaches'].append({'code': 'outside-valid-time', 'message': "The pass is dated outside the time its writer's own permission allows."})
        if slip['cancelled'] is not None:
            entry['breaches'].append({'code': 'after-cancellation', 'message': 'The person cancelled the slip before this pass.'})
    if parsed.fingerprint in passes:
        entry['problems'].append({'code': 'duplicate-id', 'message': 'This pass is already in the book.'})
    else:
        passes[parsed.fingerprint] = {
            'content': c,
            'usable': len(entry['problems']) == 0,
            # The pass this one was handed on from, if any.
            'parent': parent,
            'level': level,
            'notAllowed': not_allowed,
            # The helper's own chain of stubs, and its running totals under the pass.
            'next': 0,
            'last': None,
            'lastWhen': -INF,
            'tally': new_tally(),
        }


def _check_vouching_entry(entry, value, vouchings, ids, options):
    """A vouching record: an organisation states that a key belongs to a name."""
    without = _without(options)
    entry['signatures'] = []
    parsed = parse_record(value.get('vouching'), 'vouching')
    entry['fingerprint'] = parsed.fingerprint
    validate_vouching_content(parsed.content)
    c = parsed.content
    entry['content'] = c
    _note_id(entry, ids, c['id'])
    entry['signatures'] = _check_key_set_signatures(parsed, c['by']['keys'], without)
    if _overall(entry['signatures']) == 'invalid':
        entry['problems'].append({'code': 'signature-invalid', 'message': 'A signature on the vouching record does not fit the keys it gives.'})
    entry['verified'] = _verified_by(entry['signatures'])
    entry['signer'] = key_set_fingerprint(c['by']['keys'])
    # It counts only if the checker named this organisation as one it trusts.
    vouchers = options.get('vouchers')
    entry['counted'] = isinstance(vouchers, list) and _js.includes(vouchers, entry['signer'])
    if not entry['counted']:
        entry['notes'].append(f"This vouching record is from an organisation you did not name as trusted, so it is not counted. The fingerprint of its key set is {entry['signer']}.")
    if parsed.fingerprint in vouchings:
        entry['problems'].append({'code': 'duplicate-id', 'message': 'This vouching record is already in the book.'})
    else:
        usable = not entry['problems'] and entry['verified'] != 'none'
        vouching = {'content': c, 'signer': entry['signer'], 'usable': usable, 'counted': entry['counted'] and usable, 'withdrawn': False}
        vouchings[parsed.fingerprint] = vouching
        if usable:
            key = _vouched_key(c['for']['kind'], c['for']['key'] if c['for']['kind'] == 'person' else c['for']['keys'], c['for']['name'])
            found = vouchings.index.get(key) or {'counted': [], 'other': []}
            vouchings.index[key] = found
            # Only an organisation the checker named can add to the first list.
            # Anyone can add to the second, so it is kept short.
            if vouching['counted']:
                found['counted'].append(vouching)
            elif len(found['other']) < _MAX_UNCOUNTED:
                found['other'].append(vouching)


def _check_withdrawal_entry(entry, value, vouchings, ids, options, whole):
    """A withdrawal: the organisation ends one of its vouching records. From
    this place in the book onwards that record vouches for nothing."""
    without = _without(options)
    entry['signatures'] = []
    parsed = parse_record(value.get('withdrawal'), 'withdrawal')
    entry['fingerprint'] = parsed.fingerprint
    validate_withdrawal_content(parsed.content)
    c = parsed.content
    entry['content'] = c
    _note_id(entry, ids, c['id'])
    vouching = vouchings.get(c['vouching'])
    if not vouching:
        raise Refusal(
            'vouching-missing',
            'The vouching record this withdrawal ends is not earlier in the book.' if whole else 'The vouching record this withdrawal ends is not among the pages.',
        )
    # Only the organisation that vouched can withdraw.
    entry['signatures'] = _check_key_set_signatures(parsed, vouching['content']['by']['keys'], without)
    if _overall(entry['signatures']) == 'invalid':
        entry['problems'].append({'code': 'signature-invalid', 'message': 'A signature on the withdrawal does not fit the keys of the organisation that vouched.'})
    entry['verified'] = _verified_by(entry['signatures'])
    entry['signer'] = vouching['signer']
    if not entry['problems'] and entry['verified'] != 'none':
        vouching['withdrawn'] = True


def _check_cancellation_entry(entry, value, slips, ids, options, whole):
    """A cancellation: the person ends a slip early, with the passkey that signed it."""
    without = _without(options)
    entry['stamps'] = []
    parsed = parse_record(value.get('cancellation'), 'cancellation')
    entry['fingerprint'] = parsed.fingerprint
    validate_cancellation_content(parsed.content)
    c = parsed.content
    entry['content'] = c
    entry['slip'] = c['slip']
    _note_id(entry, ids, c['id'])
    slip = _find_slip(slips, c['slip'], whole)
    alg = slip['content']['issuer']['key']['alg']
    entry['signature'] = {'method': f'passkey ({alg})', 'alg': alg, 'state': 'invalid'}
    try:
        entry['signature']['state'] = check_passkey_signature(parsed, slip['content']['issuer'], without)
    except Exception:
        raise Refusal('cancellation-invalid', 'The cancellation was not signed with the passkey the slip names, or its passkey values do not check.') from None
    entry['verified'] = 'all' if entry['signature']['state'] == 'valid' else 'none'
    # A time-stamp is held against the cancellation's own date only where this device could confirm the cancellation.
    confirmed = entry['verified'] == 'all' and slip['verified']
    time = _check_stamps(entry, value['stamps'], parsed.fingerprint, nan_time(c['when']), options, confirmed) if 'stamps' in value else None
    if time is not None and not entry['problems'] and not confirmed:
        entry['notes'].append("The time-stamp beside this cancellation was not counted: this device could not check the cancellation's signature, or the slip's.")
    if entry['problems'] or entry['verified'] == 'none' or not slip['verified']:
        return
    # Every sound cancellation counts. The slip is cancelled from the place
    # of the first one in the book, and the earliest time that a counted
    # time-stamp gives any of them is the time used for the stubs before it.
    # So whoever keeps the book gains nothing by the order they stand in.
    first = slip['cancelled'] is None
    if first:
        slip['cancelled'] = {'index': entry['index'], 'time': None}
    else:
        entry['notes'].append('The slip had already been cancelled, earlier in the book. Every cancellation counts: the earliest time that a time-stamp you trust gives any of them is the one used.')
    if time is None:
        if first:
            entry['notes'].append('This cancellation has no time-stamp from a service you named as trusted. Only its place in the book says when it took effect.')
        return
    # The time of a cancellation is the earliest its time-stamps allow.
    made = _cancelled_at(entry, nan_time(c['when']))
    entry['stampedAt'] = format_time(made)
    _note_late_stamp(entry, made, c['when'])
    _note_block_set_aside(entry, nan_time(c['when']), _CANCELLATION_BLOCK_SET_ASIDE)
    if not whole:
        entry['notes'].append(
            'This cancellation is time-stamped. Single pages cannot show which stubs existed before that time: that needs the seals of the whole book. '
            'Here only the place of each page in the book is used.'
        )
        return
    if slip['cancelled']['time'] is not None and slip['cancelled']['time'] <= made:
        return
    slip['cancelled']['time'] = made
    _mark_not_shown_earlier(slip, made, 'This stub is not shown to have existed before the person cancelled the slip: no outside time-stamp from before the cancellation covers it.')


def _check_acknowledgement_entry(entry, value, slips, passes, ids, entries, without, whole):
    """An acknowledgement: the agent's side states that it was handed the
    person's cancellation of a slip, and when. It is signed with the keys of
    the agent the slip names or, where it names a pass, of the helper agent
    that pass names. In a book it comes after the cancellation it names."""
    entry['signatures'] = []
    parsed = parse_record(value.get('acknowledgement'), 'acknowledgement')
    entry['fingerprint'] = parsed.fingerprint
    validate_acknowledgement_content(parsed.content)
    c = parsed.content
    entry['content'] = c
    entry['slip'] = c['slip']
    _note_id(entry, ids, c['id'])
    slip = _find_slip(slips, c['slip'], whole)
    p = _find_pass(passes, c['pass'], c['slip'], whole) if 'pass' in c else None
    if p:
        entry['pass'] = c['pass']
    entry['signatures'] = _check_key_set_signatures(parsed, p['content']['to']['keys'] if p else slip['content']['agent']['keys'], without)
    if _overall(entry['signatures']) == 'invalid':
        entry['problems'].append({
            'code': 'signature-invalid',
            'message': 'A signature on the acknowledgement does not fit the keys of the helper agent the pass names.'
            if p
            else "A signature on the acknowledgement does not fit the agent's keys.",
        })
    entry['verified'] = _verified_by(entry['signatures'])
    _under_confirmed_slip(entry, slip)
    # The cancellation it names: of the same slip, and sound.
    named = next((e for e in entries if e is not entry and e['kind'] == 'cancellation' and e['fingerprint'] == c['cancellation']), None)
    if named is None:
        entry['problems'].append({
            'code': 'cancellation-not-found',
            'message': 'The cancellation this acknowledgement names is not earlier in the book.' if whole else 'The cancellation this acknowledgement names is not among the pages.',
        })
    elif named['problems'] or named.get('slip') != c['slip']:
        entry['problems'].append({'code': 'cancellation-not-found', 'message': 'The cancellation this acknowledgement names did not pass its own check, or cancels another slip.'})
    else:
        entry['cancellation'] = named['index']


def _check_held_acknowledgements(held, items, fingerprint_text, slip_fingerprint, slip, passes, entries, without, confirmed):
    """The acknowledgements handed over with the person's own copy of a
    cancellation. Each must be for exactly that cancellation, and signed with
    the keys of the slip's agent, or of a helper agent under a pass that the
    book holds. One that does not check is a problem of its own: it is not
    used, the reader is told, and the cancellation itself still counts. (The
    agent's side cannot spoil the person's copy by handing them an
    acknowledgement that does not check.)
    "confirmed": whether this device confirmed the slip and the copy, and so
    whose keys an acknowledgement is to be held against.
    Returns the problems found."""
    problems = []
    try:
        f.list_of(items, 1, MAX_ACKNOWLEDGEMENTS, 'acknowledgements')
    except Exception as e:
        return [problem_from(e)]
    seen = set()
    for record in items:
        try:
            parsed = parse_record(record, 'acknowledgement')
            validate_acknowledgement_content(parsed.content)
            a = parsed.content
            if a['cancellation'] != fingerprint_text or a['slip'] != slip_fingerprint:
                raise Refusal('acknowledgement-mismatch', 'An acknowledgement handed over with it was given for another cancellation, or under another slip.')
            if parsed.fingerprint in seen:
                raise f.fail('acknowledgements', 'the same acknowledgement is handed over twice.')
            seen.add(parsed.fingerprint)
            p = None
            if 'pass' in a:
                p = passes.get(a['pass'])
                if not p or not p['usable'] or p['content']['slip'] != slip_fingerprint:
                    raise Refusal('pass-missing', 'The pass an acknowledgement names is not in the book, was given under another slip, or did not pass its own check.')
            signatures = _check_key_set_signatures(parsed, p['content']['to']['keys'] if p else slip['content']['agent']['keys'], without)
            state = _overall(signatures)
            if state == 'invalid':
                raise Refusal('signature-invalid', 'A signature on an acknowledgement handed over with it does not fit the keys of the agent it is said to be from.')
            # The keys it was held against came from the slip: where this device could not confirm the slip or the copy, it confirmed nothing here either.
            if not confirmed:
                state = 'unavailable'
            in_book = next((e for e in entries if e['kind'] == 'acknowledgement' and e['fingerprint'] == parsed.fingerprint), None)
            held['acknowledgements'].append({
                'fingerprint': parsed.fingerprint,
                'by': 'helper' if p else 'agent',
                'pass': a['pass'] if p else None,
                'state': state,
                'signatures': signatures,
                # What it says is given only where this device confirmed who signed it.
                'when': a['when'] if state == 'valid' else None,
                'inBook': in_book['index'] if in_book else None,
            })
        except Exception as e:
            problems.append(problem_from(e))
    return problems


_ACKNOWLEDGED = (
    "the agent's side acknowledged that it was handed the person's cancellation of the slip. Both dates are the agent's own word. "
    "The acknowledgement was handed over beside the book, with the person's own copy of the cancellation."
)


def _mark_after_acknowledged(slip, slip_fingerprint, passes, entries, acknowledgement, late, strict, added, under_passes):
    """What an acknowledgement shows, where the person hands it over with their
    own copy of the cancellation: the agent's side says it was told at that
    time. A stub of that agent's own chain that is dated later was, by the
    agent's own dates, made after it was told. So was a pass that the agent
    handed on later, every pass handed on from such a pass, and every stub
    under any of them: an agent that was told cannot go on through a helper.
    Both dates are the agent's own word; the finding says so.

    It is applied after the time-stamp rule (_mark_not_shown_earlier),
    whichever order the copies were handed over in. A stub that the
    time-stamp rule already reports keeps that finding, which rests on an
    outside time-stamp, and the finding is added to."""

    def marked(b):
        return b['code'] == 'after-cancellation'

    told = nan_time(acknowledgement['when'])

    def handed_on_late(p):
        """Whether a pass was handed on by the acknowledging agent after it was told, or comes from such a pass."""
        while p:
            writer = p['content']['from'] if 'from' in p['content'] else None
            if writer == acknowledgement['pass'] and nan_time(p['content']['when']) > told:
                return True
            p = p['parent']
        return False

    def mark(entry, message):
        more = late.get(entry['breaches'])
        if any(marked(b) for b in entry['breaches']):
            return
        already = next((b for b in more if marked(b)), None) if more else None
        if already is not None:
            # Reported by the time-stamp rule: said as well, once.
            if strict.has(already) and not added.has(already):
                already['message'] += " It is also dated after the agent's side acknowledged the cancellation, by the agent's own dates."
                added.set(already, True)
            return
        finding = {'code': 'after-cancellation', 'message': message}
        if more is not None:
            more.append(finding)
        else:
            late.set(entry['breaches'], [finding])

    for stub in slip['stubs']:
        p = passes.get(stub['pass']) if 'pass' in stub else None
        if stub.get('pass') == acknowledgement['pass'] and nan_time(stub['content']['when']) > told:
            if not under_passes:
                mark(stub, f'This stub is dated after {_ACKNOWLEDGED}')
        elif under_passes and p and handed_on_late(p):
            mark(stub, f'This stub was written under a pass that was handed on after {_ACKNOWLEDGED}')
    if not under_passes:
        return
    for entry in entries:
        if entry['kind'] != 'pass' or entry.get('slip') != slip_fingerprint or entry.get('compared') is not True:
            continue
        p = passes.get(entry['fingerprint'])
        if p and handed_on_late(p):
            mark(entry, f'This pass was handed on, or comes from a pass that was handed on, after {_ACKNOWLEDGED}')


def _note_late_stamp(entry, time, when):
    """The time-stamps stand beside a cancellation, and whoever keeps it could
    put a later one in the place of an earlier one. No check can show that. A
    gap between the person's own date and the time-stamp is what it would
    leave, so the gap is pointed out."""
    if time > nan_time(when) + CLOCK_ALLOWANCE_MS:
        entry['notes'].append(
            "The time-stamp on this cancellation states a time more than 300 seconds after the date the person's device gave. Whoever keeps the book "
            'could have put a later time-stamp in the place of an earlier one. If the person holds an earlier time-stamp of this cancellation, that is the one to go by.'
        )


def _mark_not_shown_earlier(slip, time, message, late=None, strict=None):
    """With a time-stamp, a cancellation has a proven time. A stub counts as
    made before it only if an outside time-stamp shows that it existed by
    then. An agent cannot escape a cancellation by writing an earlier time.

    For a cancellation in the book the finding goes into the stub's own
    list. For one handed over beside the book it is gathered in "late", as
    the other findings are that are worked out afresh for each answer
    (_settle_late)."""

    def marked(b):
        return b['code'] == 'after-cancellation'

    for stub in slip['stubs']:
        more = late.get(stub['breaches']) if late is not None else None
        if any(marked(b) for b in stub['breaches']) or (more and any(marked(b) for b in more)):
            continue
        stamped = getattr(stub, 'stamped', None)
        if not ((INF if stamped is None else stamped) > time + CLOCK_ALLOWANCE_MS):
            continue
        finding = {'code': 'after-cancellation', 'message': message}
        # The findings made here for a copy handed over beside the book are noted, for _mark_after_acknowledged.
        if strict is not None:
            strict.set(finding, True)
        if late is None:
            stub['breaches'].append(finding)
        elif more is not None:
            more.append(finding)
        else:
            late.set(stub['breaches'], [finding])


def _check_stamps(entry, stamps, fingerprint_text, when, options, counted=True, floor=-INF):
    """The outside time-stamps beside a record. Each states that the record
    existed at a time. Returns the earliest time stated by a service the
    checker trusts, or None."""
    without = _without(options)
    stamped = from_base64url(fingerprint_text)
    methods = {'without': [m for m in without if m in ('RSA', 'ECDSA', 'Ed25519')], 'trusted': options.get('stampServices')}
    for item in decode_stamps(stamps):
        try:
            if item['kind'] == 'block':
                stamp = dict(check_block_stamp(item['proof'], item['header'], stamped, options.get('blocks')))
            else:
                stamp = {'kind': 'service', **check_stamp(item['token'], stamped, methods)}
            # A service states one time. A block's time is loose, and has two (blockstamp.py).
            if stamp.get('earliest') is None:
                stamp['earliest'] = stamp['time']
            entry['stamps'].append(stamp)
        except Exception as e:
            entry['stamps'].append({'kind': item['kind'], 'state': 'invalid', 'when': None, 'time': NAN, 'authority': None})
            entry['problems'].append(problem_from(e))
    for s in entry['stamps']:
        if s['state'] != 'untrusted':
            continue
        entry['notes'].append(
            f"A block time-stamp on this record leads to a block you did not name as trusted. The block's fingerprint is {s['authority']}."
            if s['kind'] == 'block'
            else f"A time-stamp on this record is from a service you did not name as trusted. Its certificate's fingerprint is {s['authority']}."
        )
    giving = _giving_stamps(entry, when, floor)
    time = _js_min([s['time'] for s in giving]) if giving else None
    # A record dated later than the time-stamp that covers it is not as it
    # says. Said only where the time-stamp can be counted at all.
    if counted and time is not None and time < when - CLOCK_ALLOWANCE_MS:
        entry['problems'].append({'code': 'dated-after-stamp', 'message': 'This record is dated later than a time-stamp that covers it.'})
    return time


def _behind_earlier_seal(s, floor):
    return s['kind'] == 'block' and s['time'] < floor - CLOCK_ALLOWANCE_MS


def _giving_stamps(entry, when, floor=-INF):
    """The time-stamps that give a seal its time: every counted one, and the
    earliest time any of them states is the time by which the seal existed.
    (A block states its time and two hours.) Two cases are set apart, both
    of a block that states a time far behind the true time, which a service
    settles. The reader is told of each (_note_block_set_aside, _note_block_behind).
     - Beside a time-stamp from a service, a block that states a time more
       than 300 seconds before the seal's own date, even with its two hours,
       is set aside. With no service's time-stamp beside it, nothing settles
       it, and the record reads as dated after its time-stamp.
     - A block that states a time, even with its two hours, more than 300
       seconds before the latest time a service gave a seal before this one
       ("floor") is set aside. This seal covers that seal's line, time-stamp
       included, so it cannot have existed by then.
    (For a cancellation, the time it counts from is worked out by _cancelled_at.)"""
    valid = [s for s in entry['stamps'] if s['state'] == 'valid' and not _behind_earlier_seal(s, floor)]
    if not any(s['kind'] == 'service' for s in valid):
        return valid
    return [s for s in valid if s['kind'] == 'service' or not (s['time'] < when - CLOCK_ALLOWANCE_MS)]


def _cancelled_at(entry, when):
    """The time of a cancellation: the earliest that any counted time-stamp
    beside it gives. A later time would excuse stubs made after the person
    cancelled, so every counted time-stamp is taken, of either kind: a later
    one put beside an earlier one changes nothing. A service's time is
    exact. A block's time is loose and is taken at its earliest, two hours
    before the time the block states; but never as earlier than the date the
    person signed in the cancellation itself, because by the person's own
    word it was not made before then. So nobody can move a cancellation back
    in time by having it put into a block before the date it gives."""
    times = [_js_max([s['earliest'], when]) if s['kind'] == 'block' else s['time'] for s in entry['stamps'] if s['state'] == 'valid']
    return _js_min(times) if times else None


def _note_block_set_aside(entry, when, words):
    """Two witnesses that do not agree: beside a time-stamp from a service, a
    block time-stamp that states a time long before the record's own date,
    even with its two hours. The block is set aside (_giving_stamps,
    _cancelled_at), and the reader is told."""
    valid = [s for s in entry['stamps'] if s['state'] == 'valid']
    if any(s['kind'] == 'service' for s in valid) and any(s['kind'] == 'block' and s['time'] < when - CLOCK_ALLOWANCE_MS for s in valid):
        entry['notes'].append(words)


_CANCELLATION_BLOCK_SET_ASIDE = (
    "A block time-stamp beside this cancellation states a time more than two hours before the cancellation's own date. The cancellation is not taken "
    'to have been made before the date the person signed in it. Either the block states a time far behind the true time, which the chain\'s rules allow '
    'in rare cases, or the cancellation was signed with a date later than the time it was made.'
)
_SEAL_BLOCK_SET_ASIDE = (
    "A block time-stamp beside this seal states a time more than two hours before the seal's own date. It was set aside, and the time-stamp from a "
    "service was used. Either the block states a time far behind the true time, which the chain's rules allow in rare cases, or the seal existed "
    'before the date it gives.'
)


def _note_block_behind(entry, floor):
    """A block time-stamp that states a time before a service's time-stamp on a
    seal earlier in the book. It is set aside (_giving_stamps), and the
    reader is told."""
    if any(s['state'] == 'valid' and _behind_earlier_seal(s, floor) for s in entry['stamps']):
        entry['notes'].append(_SEAL_BLOCK_BEHIND)


_SEAL_BLOCK_BEHIND = (
    'A block time-stamp beside this seal states a time that is, even with its two hours, before the time a time-stamp service gave a seal that comes '
    'before this one. This seal covers that seal and its time-stamp, so it cannot have existed by then. The block time-stamp was set aside: the block '
    "states a time far behind the true time, which the chain's rules allow in rare cases."
)


def _service_time(entry):
    """The earliest time that a counted time-stamp from a service gives a seal,
    or None where none does."""
    times = [s['time'] for s in entry['stamps'] if s['state'] == 'valid' and s['kind'] == 'service']
    return _js_min(times) if times else None


def _compare_page_seals(pages):
    """In a Show, a seal among the pages cannot be compared with the entries
    before it, and its time-stamp is credited to no page. But the seal and
    the pages that come before it are each shown to be in the book, at their
    places. So their dates can be held against one another as in a whole
    book: where they do not fit, the whole book would fail its check, one
    way or another. Which of the two is at fault, single pages cannot show:
    the seal may not belong to the book at that place. So the finding is
    given for the seal, which is the page that could not be compared, and
    never for the page before it."""
    for seal in pages:
        if seal['kind'] != 'seal' or not seal.get('content') or seal['problems'] or seal['verified'] == 'none':
            continue
        when = nan_time(seal['content']['when'])
        time = nan_time(seal['stampedAt']) if seal.get('stampedAt') else None
        after = None
        before = None
        for page in pages:
            if not (page['index'] < seal['index']) or page['problems'] or page['verified'] == 'none':
                continue
            stated = _when_of(page)
            if time is not None and stated > time + CLOCK_ALLOWANCE_MS:
                if after is None:
                    after = page['index']
            elif stated > when + CLOCK_ALLOWANCE_MS:
                if before is None:
                    before = page['index']
        if after is not None:
            seal['problems'].append({
                'code': 'dated-after-stamp',
                'message': f"Page {after}, which comes before this seal in the book, is dated later than this seal's outside time-stamp. Either that page's "
                'date is not as it says, or this seal does not fit the entries before it. Single pages cannot show which.',
            })
        if before is not None:
            seal['problems'].append({
                'code': 'time-went-backwards',
                'message': f'This seal is dated before page {before}, which comes before it in the book. Either one of the two dates is not as it says, '
                'or this seal does not fit the entries before it.',
            })
        _later_than_seals(seal, pages)
        if seal['problems']:
            seal['verified'] = 'none'


def _later_than_seals(seal, pages):
    """In a Show: a seal against the seals among the pages that come before it
    in the book. Its date may not be earlier than theirs, nor the time a
    service gave it more than 300 seconds earlier than a service gave them.
    And the seals form a chain: a seal names the seal just before it."""
    when = nan_time(seal['content']['when'])
    service = _service_time(seal) if seal['verified'] == 'all' else None
    dated = False
    stamped = False
    for p in pages:
        if p is seal or p['kind'] != 'seal' or not p.get('content') or not (p['index'] < seal['index']) or p['problems'] or p['verified'] == 'none':
            continue
        if when < nan_time(p['content']['when']):
            dated = True
        earlier = _service_time(p) if p['verified'] == 'all' else None
        if service is not None and earlier is not None and service < earlier - CLOCK_ALLOWANCE_MS:
            stamped = True
    if dated:
        seal['problems'].append({'code': 'time-went-backwards', 'message': 'This seal is dated before a seal, among the pages, that comes before it in the book. One of the two is not as it says.'})
    if stamped:
        seal['problems'].append({
            'code': 'time-went-backwards',
            'message': "This seal's time-stamp is earlier than the time-stamp of a seal, among the pages, that comes before it in the book. One of the two is not as it says.",
        })
    # The chain of seals, as far as the pages show it. Every seal that could be read has its place in it.
    others = [p for p in pages if p is not seal and p['kind'] == 'seal' and p.get('content') and p['fingerprint']]
    earlier_seals = [p for p in others if p['index'] < seal['index']]
    if 'previous' not in seal['content']:
        # It says it is the first seal of the book, and a seal comes before it.
        broken = len(earlier_seals) > 0
    else:
        # If the seal it names is among the pages, that seal comes before it, with no other seal between the two.
        named = next((p for p in others if p['fingerprint'] == seal['content']['previous']), None)
        broken = named is not None and (not (named['index'] < seal['index']) or any(p['index'] > named['index'] for p in earlier_seals))
    if broken:
        seal['problems'].append({'code': 'seal-chain-broken', 'message': 'The seal does not name the seal before it among the pages: a seal is missing, moved or changed.'})


def _counted_by(entry, floor):
    """The kind of the counted time-stamp that gives a seal its time: the one
    that states the earliest. A service's, where the two state the same."""
    giving = _giving_stamps(entry, nan_time(entry['content']['when']), floor)
    if not giving:
        return 'service'
    earliest = _js_min([s['time'] for s in giving])
    return 'service' if any(s['kind'] == 'service' and s['time'] == earliest for s in giving) else 'block'


def _dated_before_covered(when, covered, count, credited_time):
    """Whether a seal is dated before an entry it covers, where no counted
    time-stamp settles which of the two dates is wrong. An entry that failed
    its own check says nothing. One dated after the counted time-stamp is
    marked itself (_credit_stamp), and is not counted here."""
    for i in range(count):
        e = covered[i]
        if e['problems'] or e['verified'] == 'none':
            continue
        stated = _when_of(e)
        if not (stated > when + CLOCK_ALLOWANCE_MS):
            continue
        if credited_time is not None and stated > credited_time + CLOCK_ALLOWANCE_MS:
            continue
        return True
    return False


def latest_when(entry):
    """The latest time a checked entry states, in milliseconds; NaN if it states none."""
    return _when_of(entry)


def _when_of(entry):
    """The latest time an entry states: its own, and that of a countersignature
    or an approval on the same line. NaN if it states none."""
    times = []
    for holder in (entry.get('content'), entry.get('countersignature'), entry.get('approval')):
        t = holder.get('when') if isinstance(holder, dict) else None
        if isinstance(t, str):
            ms = nan_time(t)
            if ms == ms:
                times.append(ms)
    return _js_max(times) if times else NAN


def _credit_stamp(earlier, stamped_at, time):
    """An entry that a trusted time-stamp covers existed by the stated time. One
    that is dated later is not as it says. An entry keeps the earliest time
    that any seal after it shows, as "existedBy". Returns False if the entry
    was already shown to have existed by then."""
    before = getattr(earlier, 'stamped', None)
    if before is not None and before <= time:
        return False
    earlier.stamped = time
    # The time that a seal's or a cancellation's own time-stamps give it is
    # another matter, and is kept apart, as "stampedAt": a cancellation does
    # not count from the time of a seal after it.
    earlier['existedBy'] = stamped_at
    if _when_of(earlier) > time + CLOCK_ALLOWANCE_MS and not any(p['code'] == 'dated-after-stamp' for p in earlier['problems']):
        earlier['problems'].append({'code': 'dated-after-stamp', 'message': 'This entry is dated later than the outside time-stamp that covers it.'})
        earlier['verified'] = 'none'
    return True


def _check_seal_entry(entry, value, seals, ids, options, before, entries, as_page=False):
    """A seal: the recorder's signed statement of the top fingerprint and the
    number of entries before it, with outside time-stamps beside it.

    seals: the state of the seals so far, or a fresh state for a seal that
    stands alone. before: works out the entries before the seal, where they
    are at hand. entries: the entries so far, so that the ones a time-stamp
    covers can be marked. as_page: whether the seal is a single page of a
    Show, with nothing to compare it with."""
    without = _without(options)
    entry['signatures'] = []
    entry['stamps'] = []
    parsed = parse_record(value.get('seal'), 'seal')
    entry['fingerprint'] = parsed.fingerprint
    validate_seal_content(parsed.content)
    c = parsed.content
    entry['content'] = c
    _note_id(entry, ids, c['id'])
    seals['count'] += 1

    # The recorder's three signatures: all must check.
    entry['signatures'] = _check_key_set_signatures(parsed, c['by']['keys'], without)
    if _overall(entry['signatures']) == 'invalid':
        entry['problems'].append({'code': 'signature-invalid', 'message': 'A signature on the seal does not fit the keys the seal gives.'})
    entry['verified'] = _verified_by(entry['signatures'])
    entry['sealer'] = key_set_fingerprint(c['by']['keys'])
    seal_keys = options.get('sealKeys')
    if isinstance(seal_keys, list):
        if not _js.includes(seal_keys, entry['sealer']):
            entry['problems'].append({'code': 'sealer-not-expected', 'message': 'The seal was signed with keys other than the ones expected.'})
    else:
        entry['notes'].append('The keys that signed this seal were not compared with keys you already trust. The name on the seal is only a label.')

    # The seal against the entries before it, and against the seal before it.
    when = nan_time(c['when'])
    at = before() if before else None
    # A seal sits after exactly as many entries as it covers.
    if not at and c['size'] != entry['index']:
        entry['problems'].append({'code': 'seal-mismatch', 'message': 'A seal sits after exactly as many entries as it covers, and this one does not.'})
    if as_page:
        entry['notes'].append(
            'This seal is shown as a single page. It could not be compared with the entries before it, so its time-stamp is not taken to show when any '
            'other page existed. Its dates are still held against the pages that come before it in the book.'
        )
    if at:
        if c['size'] != at['size'] or c['root'] != at['root']:
            entry['problems'].append({'code': 'seal-mismatch', 'message': 'The seal does not fit the entries before it: an entry was changed, added or removed after the seal was made.'})
        if (c['previous'] if 'previous' in c else None) != seals['last']:
            entry['problems'].append({'code': 'seal-chain-broken', 'message': 'The seal does not name the seal before it: a seal is missing, moved or changed.'})
        if when < seals['lastWhen']:
            entry['problems'].append({'code': 'time-went-backwards', 'message': 'This seal is dated before the seal ahead of it.'})
        seals['last'] = parsed.fingerprint
        seals['lastWhen'] = when

    # The outside time-stamps. Each states that this seal existed at a time.
    # They are read only for a seal whose own signatures did not fail. The
    # latest time a service gave a seal before this one is the "floor": a
    # block time-stamp that states a time before it is set aside (_giving_stamps).
    floor = seals['lastStampTime'] if seals['lastStampTime'] is not None else -INF
    # The same floor holds for the seal's own date. A seal covers the lines of
    # the seals before it, time-stamps included, so it cannot have been made
    # before the latest time a service gave one of them.
    if when < floor - CLOCK_ALLOWANCE_MS:
        entry['problems'].append({
            'code': 'time-went-backwards',
            'message': 'This seal is dated before the time that a time-stamp service gave a seal that comes before it. It covers that seal and its '
            'time-stamp, so it cannot have been made by then.',
        })
    stamped_time = None
    if 'stamps' in value and _overall(entry['signatures']) != 'invalid':
        stamped_time = _check_stamps(entry, value['stamps'], parsed.fingerprint, when, options, entry['verified'] == 'all', floor)
    if 'stamps' in value and _overall(entry['signatures']) == 'invalid':
        decode_stamps(value['stamps'])

    # A seal counts as signed only if all three of its signatures were
    # checked. Only then is a time-stamp on it credited.
    credited = not entry['problems'] and entry['verified'] == 'all' and stamped_time is not None
    if stamped_time is not None and not entry['problems'] and entry['verified'] != 'all':
        entry['notes'].append("The time-stamp beside this seal was not counted: this device could not check all three of the seal's signatures.")
    if not entry['problems'] and entry['verified'] == 'all':
        _note_block_behind(entry, floor)

    # A seal dated before an entry it covers: one of the two dates is not as
    # it says. Where a counted time-stamp settles which (the entry is dated
    # after the time-stamp too), the entry is marked instead (below). Where
    # none does, the seal is where the two meet.
    if at and seals['latest'] > when + CLOCK_ALLOWANCE_MS and _dated_before_covered(when, entries, len(entries) - 1, stamped_time if credited else None):
        entry['problems'].append({'code': 'time-went-backwards', 'message': 'This seal is dated before an entry it covers. One of the two dates is not as it says.'})
    if not credited or entry['problems']:
        return
    time = stamped_time
    entry['stampedAt'] = format_time(time)
    _note_block_set_aside(entry, when, _SEAL_BLOCK_SET_ASIDE)
    service = _service_time(entry)
    if not at:
        # Among the pages of a Show, the services' times are held against one
        # another later (_later_than_seals). The floor for a block time-stamp on
        # a seal further on is kept here, as in a whole book.
        if service is not None and service > (seals['lastStampTime'] if seals['lastStampTime'] is not None else -INF):
            seals['lastStampTime'] = service
        return
    # A later seal cannot have been time-stamped by a service before an
    # earlier one: not before the latest time a service gave any seal so
    # far. A block time-stamp is not reported in this way: it is made hours
    # after the seal, and its time is only right to within two hours. One
    # that states a time before that floor is set aside (_giving_stamps).
    if service is not None:
        if service < seals['lastStampTime'] - CLOCK_ALLOWANCE_MS:
            entry['problems'].append({'code': 'time-went-backwards', 'message': "This seal's time-stamp is earlier than the time-stamp of a seal before it."})
            return
        if service > seals['lastStampTime']:
            seals['lastStampTime'] = service
    by = _counted_by(entry, floor)
    # What a trusted time-stamp covers: every entry before the seal existed
    # by then. An entry dated later than that is not as it says. The
    # earliest time that any seal after an entry shows is the one that
    # counts for it. Going back from the seal, the entries already shown to
    # have existed earlier are left as they are, with everything before them.
    for i in range(len(entries) - 2, -1, -1):
        if not _credit_stamp(entries[i], entry['stampedAt'], time):
            break
    seals['next'] = len(entries) - 1
    seals['sealed'] = {'entries': c['size'], 'when': entry['stampedAt'], 'seal': entry['index'], 'by': by}


# A stub may have with it, on the same line, the service's countersignature
# and the person's approval.
_STUB_ENTRIES = ['stub', 'countersignature,stub', 'approval,stub', 'approval,countersignature,stub']


def _find_slip(slips, fp, whole):
    slip = slips.get(fp)
    if not slip:
        raise Refusal('slip-missing', 'The slip this entry relies on is not earlier in the book.' if whole else 'The slip this entry relies on is not among the pages.')
    if not slip['usable']:
        raise Refusal('slip-unusable', 'The slip this entry relies on did not pass its own check.')
    return slip


def _under_confirmed_slip(entry, slip):
    """What sits under a slip this device could not confirm is not evidence
    either, whatever its own signatures say: the keys it was checked against
    came from that slip."""
    if slip['verified'] or entry['verified'] == 'none':
        return
    entry['verified'] = 'none'
    entry['notes'].append('The slip this entry relies on could not be confirmed on this device, so this entry is not shown.')


def check_approval_record(record, request, slip_fingerprint, slip, ids, without):
    """Check the person's approval of one action against that action: it must be
    for exactly this request, under this slip, not used before, and signed
    with the passkey the slip names. Used by the checker and by the check
    before acting. Returns {state, when, alg, fingerprint}; raises a Refusal."""
    approval = parse_record(record, 'approval')
    validate_approval_content(approval.content)
    a = approval.content
    if a['slip'] != slip_fingerprint or request_of(a) != request_of(request):
        raise Refusal('approval-mismatch', 'The approval was given for something else.')
    if 'approval' in request and request['approval'] != approval.fingerprint:
        raise Refusal('approval-mismatch', 'The approval with this stub is not the one the stub names.')
    if a['id'] in ids.approvals:
        raise Refusal('approval-reused', 'This approval has already been used for another stub.')
    if a['id'] in ids:
        raise Refusal('duplicate-id', 'Another record has the same unique number.')
    ids.add(a['id'])
    ids.approvals.add(a['id'])
    try:
        state = check_passkey_signature(approval, slip['content']['issuer'], without)
    except Exception:
        raise Refusal('approval-invalid', 'The approval was not signed with the passkey the slip names, or its passkey values do not check.') from None
    return {'state': state, 'when': a['when'], 'alg': slip['content']['issuer']['key']['alg'], 'fingerprint': approval.fingerprint}


def check_countersignature(record, stub_fingerprint, service, without, into=None):
    """Check a countersignature against the stub it was made for and the keys
    the slip gives for the service. Used by the checker, and by the stub
    writer before it puts a countersignature into its book. "into" is filled
    in as the check goes. Returns {state, signatures, when}; raises a Refusal."""
    if into is None:
        into = {'state': 'invalid', 'signatures': []}
    counter = parse_record(record, 'countersignature')
    validate_countersignature_content(counter.content)
    if counter.content['stub'] != stub_fingerprint:
        raise Refusal('countersignature-wrong-stub', 'The countersignature was made for a different stub.')
    if not keys_of(service):
        raise Refusal('countersignature-not-possible', 'The slip names no keys for a service that could have countersigned this stub.')
    into['when'] = counter.content['when']
    into['signatures'] = _check_key_set_signatures(counter, service['keys'], without)
    into['state'] = _overall(into['signatures'])
    if into['state'] == 'invalid':
        raise Refusal('countersignature-invalid', "A signature on the countersignature does not fit the service's keys.")
    return into


def _note_id(entry, ids, record_id):
    if record_id in ids:
        entry['problems'].append({'code': 'duplicate-id', 'message': 'Another record has the same unique number.'})
    ids.add(record_id)


def _check_refusal_entry(entry, value, slips, ids, without, whole):
    """A refusal: what a service says it refused. It is the service's own
    statement, signed with the keys the refusal itself gives."""
    entry['signatures'] = []
    parsed = parse_record(value.get('refusal'), 'refusal')
    entry['fingerprint'] = parsed.fingerprint
    validate_refusal_content(parsed.content)
    c = parsed.content
    entry['content'] = c
    entry['slip'] = c['slip']
    _note_id(entry, ids, c['id'])
    slip = _find_slip(slips, c['slip'], whole)
    entry['signatures'] = _check_key_set_signatures(parsed, c['by']['keys'], without)
    if _overall(entry['signatures']) == 'invalid':
        entry['problems'].append({'code': 'signature-invalid', 'message': 'A signature on the refusal does not fit the keys the refusal gives.'})
    entry['verified'] = _verified_by(entry['signatures'])
    entry['signer'] = key_set_fingerprint(c['by']['keys'])
    _under_confirmed_slip(entry, slip)
    # Is this a service the slip names? Only its keys can say.
    keys = canonical_json(c['by']['keys'])
    named = next((s for s in slip['content']['with'] if keys_of(s) and canonical_json(s['keys']) == keys), None)
    entry['service'] = named['id'] if named else None


def _check_terms_entry(entry, value, terms, ids, without):
    """A service's terms for agents, signed with the keys the terms themselves give."""
    entry['signatures'] = []
    parsed = parse_record(value.get('terms'), 'terms')
    entry['fingerprint'] = parsed.fingerprint
    try:
        validate_terms_content(parsed.content)
        c = parsed.content
        entry['content'] = c
        _note_id(entry, ids, c['id'])
        entry['signatures'] = _check_key_set_signatures(parsed, c['by']['keys'], without)
        if _overall(entry['signatures']) == 'invalid':
            entry['problems'].append({'code': 'signature-invalid', 'message': 'A signature on the terms does not fit the keys the terms give.'})
        entry['verified'] = _verified_by(entry['signatures'])
        # 5. Whose keys signed these terms: a name is only a label.
        entry['signer'] = key_set_fingerprint(c['by']['keys'])
    except Exception as e:
        entry['problems'].append(problem_from(e))
    if parsed.fingerprint in terms:
        entry['problems'].append({'code': 'duplicate-id', 'message': 'These terms are already in the book.'})
    else:
        terms[parsed.fingerprint] = {
            'content': entry.get('content'),
            'usable': len(entry['problems']) == 0,
            'verified': len(entry['problems']) == 0 and entry['verified'] != 'none',
        }


def _check_stub_entry(entry, value, slips, terms, passes, ids, without, whole):
    entry['signatures'] = []
    # A countersignature the line holds is "unchecked" until it is checked,
    # so that a stub whose slip fails is not counted as one-sided.
    entry['countersignature'] = {'state': 'unchecked' if 'countersignature' in value else 'absent', 'signatures': []}
    entry['approval'] = {'state': 'absent'}
    # Whether this stub was compared with its slip. It is not, if the stub or
    # the slip could not be confirmed.
    entry['compared'] = False

    parsed = parse_record(value.get('stub'), 'stub')
    entry['fingerprint'] = parsed.fingerprint
    validate_stub_content(parsed.content)
    c = parsed.content
    entry['content'] = c
    entry['slip'] = c['slip']

    _note_id(entry, ids, c['id'])
    slip = _find_slip(slips, c['slip'], whole)

    # A helper agent's stub names the pass it acts under: it is signed with
    # the helper's keys, and sits in the helper's own chain.
    p = _find_pass(passes, c['pass'], c['slip'], whole) if 'pass' in c else None
    chain = p if p else slip
    if p:
        entry['pass'] = c['pass']

    # The agent's two signatures: both must check.
    entry['signatures'] = _check_key_set_signatures(parsed, p['content']['to']['keys'] if p else slip['content']['agent']['keys'], without)
    if _overall(entry['signatures']) == 'invalid':
        entry['problems'].append({
            'code': 'signature-invalid',
            'message': 'A signature on the stub does not fit the keys of the helper agent the pass names.' if p else "A signature on the stub does not fit the agent's keys.",
        })
    entry['verified'] = _verified_by(entry['signatures'])
    _under_confirmed_slip(entry, slip)

    # Its place in the chain.
    when = nan_time(c['when'])
    if whole:
        if c['seq'] != chain['next'] or (c['seq'] > 0 and c.get('previous') != chain['last']):
            entry['problems'].append({'code': 'chain-broken', 'message': 'The chain is broken here: a stub is missing, moved, repeated or changed.'})
        if when < chain['lastWhen']:
            entry['problems'].append({'code': 'time-went-backwards', 'message': 'This stub is dated before the stub ahead of it.'})
        # Carry on from this stub, so that one break is reported once.
        chain['next'] = c['seq'] + 1
        chain['last'] = parsed.fingerprint
        chain['lastWhen'] = when

    # The countersignature, if there is one.
    service = next((s for s in slip['content']['with'] if s['id'] == c['with']), None) if 'with' in c else None
    if 'countersignature' in value:
        entry['countersignature']['state'] = 'invalid'
        try:
            check_countersignature(value['countersignature'], parsed.fingerprint, service, without, entry['countersignature'])
        except Exception as e:
            entry['problems'].append(problem_from(e))

    # The person's approval of this one action, if there is one. It is signed
    # with the passkey the slip names, and must be for exactly this action.
    if 'approval' in value:
        entry['approval']['state'] = 'invalid'
        try:
            # A stub must name the approval that is with it.
            if 'approval' not in c:
                raise Refusal('approval-mismatch', 'The stub does not name the approval that is with it.')
            checked = check_approval_record(value['approval'], c, c['slip'], slip, ids, without)
            entry['approval'] = {'state': checked['state'], 'when': checked['when'], 'alg': checked['alg']}
            # The stub names the approval, so it was signed after the approval
            # was written. A stub dated before its approval is not as it says.
            if nan_time(checked['when']) > when + CLOCK_ALLOWANCE_MS:
                raise Refusal('approval-dated-after-stub', 'The approval is dated later than the stub that carries it.')
        except Exception as e:
            entry['problems'].append(problem_from(e))
    elif 'approval' in c:
        entry['problems'].append({'code': 'approval-not-found', 'message': 'The stub names an approval that is not with it.'})

    # The service's terms for agents, if the stub relies on them.
    terms_content = None
    terms_confirmed = True
    if 'terms' in c:
        t = terms.get(c['terms'])
        if not t:
            entry['problems'].append({
                'code': 'terms-not-found',
                'message': 'The terms this stub relies on are not earlier in the book.' if whole else 'The terms this stub relies on are not among the pages.',
            })
        elif not t['usable']:
            entry['problems'].append({'code': 'terms-unusable', 'message': 'The terms this stub relies on did not pass their own check.'})
        elif not keys_of(service) or canonical_json(service['keys']) != canonical_json(t['content']['by']['keys']):
            entry['problems'].append({'code': 'terms-mismatch', 'message': 'The terms this stub relies on were not signed with the keys the slip gives for the service it names.'})
        else:
            terms_content = t['content']
            terms_confirmed = t['verified']

    # What the stub shows about the agent. Only a stub that is itself sound,
    # that this device could confirm at least in part, under a slip this
    # device confirmed, is evidence of anything.
    if entry['problems'] or entry['verified'] == 'none' or not slip['verified'] or not terms_confirmed:
        return
    entry['compared'] = True
    shown = compare_with_slip(
        slip['content'],
        slip['tally'] if whole else None,
        c,
        {'service': service, 'terms': terms_content, 'cancelled': slip['cancelled'] is not None, 'late': entry['breaches']},
    )
    slip['stubs'].append(entry)
    # A helper's stub is compared with the slip, as every stub is, and also
    # with the pass it acts under and with every pass above that one: what a
    # helper holds, it holds under each of them, and their totals take in
    # what is done further down. A finding already given is not repeated.
    # (There are at most ten: a pass further down is refused.)
    if p:
        given = list(shown['breaches'])
        q = p
        while q:
            under = compare_with_slip(
                pass_as_slip(q['content']),
                q['tally'] if whole else None,
                c,
                {'service': service, 'what': 'pass' if q is p else 'earlier-pass', 'late': entry['breaches']},
            )
            for b in under['breaches']:
                if any(x['code'] == b['code'] for x in given):
                    continue
                given.append(b)
                entry['breaches'].append(b)
            q = q['parent']
        if p['notAllowed']:
            entry['breaches'].append({'code': 'pass-not-allowed', 'message': 'This stub was written under a pass that the slip does not allow.'})
    entry['breaches'].extend(shown['breaches'])
    if shown['running'] is not None:
        entry['running'] = shown['running']
    entry['needs'] = shown['needs']
    if 'countersignature' in shown['needs'] and entry['countersignature']['state'] == 'absent':
        entry['breaches'].append({'code': 'countersignature-missing', 'message': 'The slip asks for the other side to countersign this action, and there is no countersignature.'})
    if 'approval' in shown['needs'] and entry['approval']['state'] == 'absent':
        entry['breaches'].append({'code': 'approval-missing', 'message': "The slip asks for the person's own approval of this action, and there is none."})


def _summarise(entries, book_problems, sealed=None, held=()):
    # Methods this device lacked, and whether any signature was never reached
    # because its entry, or the whole record, could not be read or used.
    missing = set()
    skipped = len(book_problems) > 0 or len(entries) == 0
    counts = {
        'slips': 0, 'stubs': 0, 'countersigned': 0, 'oneSided': 0, 'approved': 0, 'refusals': 0,
        'terms': 0, 'seals': 0, 'cancellations': 0, 'acknowledgements': 0, 'vouchings': 0, 'passes': 0,
    }

    def note(signatures):
        nonlocal skipped
        if len(signatures) == 0:
            skipped = True
        for s in signatures:
            if s['state'] == 'unavailable':
                missing.add(s['method'])

    for e in entries:
        kind = e['kind']
        if kind == 'slip':
            counts['slips'] += 1
            if e['signature']['state'] == 'unavailable':
                missing.add(e['signature']['alg'])
            elif e['signature']['state'] == 'unchecked':
                skipped = True
        elif kind == 'stub':
            counts['stubs'] += 1
            note(e.get('signatures') or [])
            counter = e.get('countersignature') or {'state': 'absent', 'signatures': []}
            if counter['state'] == 'absent':
                counts['oneSided'] += 1
            else:
                note(counter['signatures'])
                # Counted only when both of its signatures were confirmed here.
                if counter['state'] == 'valid':
                    counts['countersigned'] += 1
            approval = e.get('approval') or {'state': 'absent'}
            if approval['state'] == 'unavailable':
                missing.add(approval['alg'])
            elif approval['state'] == 'valid':
                counts['approved'] += 1
        elif kind in ('refusal', 'terms'):
            counts['refusals' if kind == 'refusal' else 'terms'] += 1
            note(e.get('signatures') or [])
        elif kind == 'seal':
            counts['seals'] += 1
            note(e.get('signatures') or [])
            for s in e.get('stamps') or []:
                if s['state'] == 'unavailable':
                    missing.add("the time-stamp service's method")
        elif kind == 'cancellation':
            counts['cancellations'] += 1
            if not e.get('signature'):
                skipped = True
            elif e['signature']['state'] == 'unavailable':
                missing.add(e['signature']['alg'])
            for s in e.get('stamps') or []:
                if s['state'] == 'unavailable':
                    missing.add("the time-stamp service's method")
        elif kind in ('vouching', 'withdrawal', 'pass', 'acknowledgement'):
            if kind == 'vouching':
                counts['vouchings'] += 1
            if kind == 'pass':
                counts['passes'] += 1
            if kind == 'acknowledgement':
                counts['acknowledgements'] += 1
            note(e.get('signatures') or [])
        else:
            skipped = True
    for h in held:
        for s in h['stamps']:
            if s['state'] == 'unavailable':
                missing.add("the time-stamp service's method")
        for a in h['acknowledgements']:
            note(a['signatures'])
    problem_found = len(book_problems) > 0 or any(e['problems'] for e in entries)
    fully_checked = not skipped and len(missing) == 0
    first_breach = next((e for e in entries if e['breaches']), None)
    # "Within its slip" is said only if every stub, and every pass, was
    # compared with what it rests on, and none was found outside it.
    all_compared = all((e.get('compared') is True) if e['kind'] in ('stub', 'pass') else e['kind'] != 'unreadable' for e in entries)
    return {
        'intact': not problem_found and fully_checked,
        'problemFound': problem_found,
        'fullyChecked': fully_checked,
        'methodsMissing': _js.sort_strings(missing),
        'withinSlips': first_breach is None and all_compared and not problem_found,
        'firstBreach': first_breach['index'] if first_breach else None,
        'counts': counts,
        # How far an outside time-stamp from a trusted service reaches, if any does.
        'sealed': None if problem_found else sealed,
        'limits': [*LIMITS[:-1], _stamped_words(sealed)] if sealed and not problem_found else list(LIMITS),
    }


def _unused_disclosures(result, options):
    """Disclosures are handed over as {fingerprint of a slip: [disclosures]}.
    Anything else is refused, never set aside: the person handed it over to
    have fields revealed. Where no such slip is among the entries, the
    disclosures were not used, and the person is told."""
    if 'disclosures' not in options:
        return
    handed = options['disclosures']
    if not isinstance(handed, dict):
        raise f.fail('disclosures', 'must be laid out as {the fingerprint of a slip: [its disclosures]}.')
    slips = {e['fingerprint'] for e in result['entries'] if e['kind'] == 'slip'}
    if any(fp not in slips for fp in handed):
        result['notes'].append('Disclosures were handed over for a slip that is not here. They were not used.')


def _check_held(result, reader, options, late, beside):
    """Cancellations that the person kept, handed over beside the book.

    Whoever keeps a book can leave a cancellation out of it, or put a later
    time-stamp in the place of the person's own. The person's own copy, with
    its time-stamp, settles both: it is checked against the slip's passkey
    as a cancellation in the book is, and the earliest time a counted
    time-stamp gives it is used. A stub then counts as made before the
    cancellation only if an outside time-stamp shows that it existed by then.

    A copy that does not pass its check is a problem, never dropped: the
    person handed it over to have it counted.

    Nothing the reader keeps is changed: what the copies show about the
    stubs is gathered in "late", and the slips they cancel in "beside"."""
    slips, passes = reader.slips, reader.passes
    if 'cancellations' not in options:
        return
    handed = options['cancellations']
    without = _without(options)
    # Up to sixteen, none included: an empty list is what a stub writer that holds none hands back.
    f.list_of(handed, 0, MAX_HELD, 'cancellations')
    seen = set()
    # What the acknowledgements show is applied once every copy has been through the time-stamp rule.
    acknowledged_copies = []
    strict = _js.IdentityMap()
    # The problems with acknowledgements, by the place of their copy: reported, without setting the copy aside.
    acknowledgement_problems = []
    for i, value in enumerate(handed):
        held = {'kind': 'cancellation', 'fingerprint': None, 'slip': None, 'inBook': None, 'used': False, 'problems': [], 'notes': [], 'stamps': [], 'acknowledgements': []}
        result['held'].append(held)
        try:
            f.members(value, ['cancellation'], ['acknowledgements', 'stamps'], f'cancellations[{i}]')
            parsed = parse_record(value.get('cancellation'), 'cancellation')
            held['fingerprint'] = parsed.fingerprint
            validate_cancellation_content(parsed.content)
            c = parsed.content
            held['content'] = c
            held['slip'] = c['slip']
            if parsed.fingerprint in seen:
                raise f.fail(f'cancellations[{i}]', 'the same cancellation is handed over twice.')
            seen.add(parsed.fingerprint)
            slip = slips.get(c['slip'])
            if not slip or not slip['usable']:
                raise Refusal('slip-missing', 'The slip it names is not in the book, or did not pass its own check.')
            alg = slip['content']['issuer']['key']['alg']
            held['signature'] = {'method': f'passkey ({alg})', 'alg': alg, 'state': 'invalid'}
            try:
                held['signature']['state'] = check_passkey_signature(parsed, slip['content']['issuer'], without)
            except Exception:
                raise Refusal('cancellation-invalid', 'It was not signed with the passkey the slip names, or its passkey values do not check.') from None
            confirmed = held['signature']['state'] == 'valid' and slip['verified']
            time = _check_stamps(held, value['stamps'], parsed.fingerprint, nan_time(c['when']), options, confirmed) if 'stamps' in value else None
            if 'acknowledgements' in value:
                found = _check_held_acknowledgements(held, value['acknowledgements'], parsed.fingerprint, c['slip'], slip, passes, result['entries'], without, confirmed)
                for p in found:
                    acknowledgement_problems.append((i, p))
                if found:
                    held['notes'].append('An acknowledgement handed over with it did not pass its check, so that acknowledgement was not used. See the problems at the top.')
            if held['problems']:
                continue
            if held['signature']['state'] != 'valid' or not slip['verified']:
                held['notes'].append('This device could not confirm it, or the slip it names, so it was not used.')
                continue
            held['used'] = True
            # The check before acting allows nothing under a slip the person has cancelled.
            beside.add(c['slip'])
            in_book = next((e for e in result['entries'] if e['kind'] == 'cancellation' and e['fingerprint'] == parsed.fingerprint), None)
            held['inBook'] = in_book['index'] if in_book else None
            # What the agent's side acknowledged, where this device confirmed who signed.
            told = [a for a in held['acknowledgements'] if a['state'] == 'valid']
            if len(held['acknowledgements']) > len(told):
                held['notes'].append('This device could not check an acknowledgement handed over with it, so that acknowledgement was not used.')
            if not in_book and told:
                first = _js.sort_strings([a['when'] for a in told])[0]
                held['notes'].append(
                    f"The book does not hold this cancellation, though the agent's side acknowledged at {first} (its own word for the time) that it was handed it. "
                    'So it was left out of the book, or was still to be written into it when this copy of the book was made.'
                )
            elif not in_book:
                held['notes'].append('The book does not hold this cancellation: whoever keeps the book left it out, or was never given it.')
            elif in_book['problems']:
                held['notes'].append(f"The book holds this cancellation at entry {in_book['index']}, but that entry did not pass its check.")
            for a in told:
                acknowledged_copies.append((slip, c['slip'], a))
            if time is None:
                held['notes'].append(
                    "It has no time-stamp from a service you named as trusted, so it cannot be placed in time. A stub is reported because of it only where the stub is dated after the agent's side acknowledged it."
                    if told
                    else 'It has no time-stamp from a service you named as trusted, so it cannot be placed in time, and no stub is marked because of it.'
                )
                continue
            made = _cancelled_at(held, nan_time(c['when']))
            held['stampedAt'] = format_time(made)
            _note_late_stamp(held, made, c['when'])
            _note_block_set_aside(held, nan_time(c['when']), _CANCELLATION_BLOCK_SET_ASIDE)
            _mark_not_shown_earlier(
                slip,
                made,
                "This stub is not shown to have existed before the person cancelled the slip: no outside time-stamp from before the cancellation covers it. "
                "The person's own copy of the cancellation was handed over beside the book.",
                late,
                strict,
            )
        except Exception as e:
            held['problems'].append(problem_from(e))
    added = _js.IdentityMap()
    # First what each acknowledging agent did itself after it was told, for every acknowledgement; then what was
    # done under a pass handed on late. So the words a stub is given do not depend on the order of the acknowledgements.
    for under_passes in (False, True):
        for slip, slip_fingerprint, a in acknowledged_copies:
            _mark_after_acknowledged(slip, slip_fingerprint, passes, result['entries'], a, late, strict, added, under_passes)
    for i, held in enumerate(result['held']):
        for p in held['problems']:
            result['problems'].append({'code': p['code'], 'message': f"Cancellation {i + 1} of those handed over beside the book did not pass its check, so it was not used. {p['message']}"})
    for i, p in acknowledgement_problems:
        result['problems'].append({
            'code': p['code'],
            'message': f'An acknowledgement handed over with cancellation {i + 1} of those beside the book did not pass its check, so it was not used. '
            f"The cancellation itself was not set aside because of it. {p['message']}",
        })


_BLOCK = re.compile(r'[0-9a-fA-F]{64}')


def _check_blocks_option(options):
    """The blocks a person trusts are named by their fingerprints: 64 hex
    characters each. Anything else is refused, never set aside."""
    if 'blocks' not in options:
        return
    blocks = options['blocks']
    sound = isinstance(blocks, list) and len(blocks) <= MAX_ENTRIES and all(isinstance(b, str) and _BLOCK.fullmatch(b) for b in blocks)
    if not sound:
        raise f.fail('blocks', 'must be a list of block fingerprints, each 64 hex characters, at most 100,000.')


def _compare_trusted(result, options):
    """Compare the top fingerprint and the number of entries with what the
    checker already trusts, if it was given either."""
    if 'expectedRoot' in options and not _js.strict_equal(options['expectedRoot'], result['root']):
        raise Refusal('root-mismatch', 'The top fingerprint is not the one expected.')
    if 'expectedSize' in options and not _js.strict_equal(options['expectedSize'], result['size']):
        raise Refusal('root-mismatch', 'The number of entries is not the one expected.')


def check_book(text, options=None, **named):
    """Check a whole book.

    The answer always has the same shape, whatever the book holds. It never
    raises for a bad record: a failed check is a normal answer. The options
    are those of the JavaScript library, by its names or in Python's way:
    issuer_keys, expected_root, expected_size, stamp_services, blocks,
    seal_keys, vouchers, disclosures, cancellations, without_methods. See
    the README, "What the checker returns". The content of an entry that
    has problems, or whose "verified" is "none", is given as it was read,
    for whoever must find out what went wrong. It is unverified: never show
    it as fact."""
    return check_book_keeping_state(text, fixed_options(options, **named))['result']


def check_book_keeping_state(text, options=None):
    """Check a whole book, and also hand back the running state of every slip,
    for the check before acting (guard.py). Not part of the public interface."""
    carried = start_carried(fixed_options(options))
    carry_on(carried, text)
    return answer_of(carried)


# --- a book that is read once and then carried on ---
#
# A whole check is: start, read every line, give the answer. The three
# steps are kept apart here, so that more lines can be read after an
# answer was given, without reading the earlier ones again. check_book does
# the three in one go; open_checker and the stub writer carry a book on.
# There is one way of reading a line (_read_line), so a book that is
# carried on gets the answer that a whole check gives.


class _Carried:
    __slots__ = ('options', 'reader', 'any', 'closed', 'failure')


def start_carried(options=None):
    """Start reading a book. Not part of the public interface."""
    if not isinstance(options, Mapping):
        options = _Fixed()
    carried = _Carried()
    carried.options = options
    carried.reader = _Reader(options, True)
    # Whether any text was handed over at all, and whether it ended with a line feed.
    carried.any = False
    carried.closed = True
    # A problem with the book as a whole, which no later line can mend: an option that cannot be used, or too many entries.
    carried.failure = None
    try:
        _check_blocks_option(options)
    except Exception as e:
        carried.failure = problem_from(e)
    return carried


def carry_on(carried, text):
    """Read more of a book: whole lines, each ending with a line feed. (The
    last line of all may lack its line feed, as in a whole check; nothing
    can then be added after it.) Not part of the public interface."""
    if not isinstance(text, str) or len(text) == 0:
        return
    if carried.any and not carried.closed:
        raise ValueError('The book so far does not end with a line feed, so nothing can be added to it.')
    carried.any = True
    carried.closed = text.endswith('\n')
    if carried.failure:
        return
    reader = carried.reader
    try:
        lines = _split_lines(text)
        if len(reader.entries) + len(lines) > MAX_ENTRIES:
            raise Refusal('too-large', 'The book holds more than 100,000 entries.')
    except Exception as e:
        carried.failure = problem_from(e)
        return
    for line in lines:
        _read_line(reader, len(reader.entries), line)


def answer_of(carried, options=None):
    """The answer for a book as it stands. It changes nothing that the reader
    keeps, so more lines can be read afterwards, and the answer asked for
    again. Not part of the public interface.

    options: the options for what is handed over beside the book
    (cancellations, disclosures) and for what is expected of it
    (expectedRoot, expectedSize); the options the lines were read with by
    default. Returns {"result", "state", "beside"}: the answer; the running
    state of every slip, for the check before acting; and the slips that a
    cancellation handed over beside the book cancels."""
    if options is None:
        options = carried.options
    result = {'format': 'provared-book-draft-v0', 'size': 0, 'root': None, 'problems': [], 'notes': [], 'entries': [], 'held': [], 'summary': None}
    state = {'slips': {}, 'terms': {}, 'passes': {}, 'ids': _Ids()}
    sealed = None
    late = _js.IdentityMap()
    beside = set()
    if not isinstance(options, Mapping):
        options = _Fixed()
    try:
        if not carried.any:
            raise Refusal('not-json', 'There is no record to check.')
        if carried.failure:
            raise Refusal(carried.failure['code'], carried.failure['message'])
        reader = carried.reader
        result['size'] = len(reader.entries)
        # Until the answer is put together, the entries are looked at as the reader keeps them.
        result['entries'] = reader.entries
        late = _settle_late(reader)
        state = {'slips': reader.slips, 'terms': reader.terms, 'passes': reader.passes, 'ids': reader.ids}
        sealed = reader.seals['sealed']
        result['root'] = to_base64url(reader.tree.root())
        result['problems'].extend(reader.handed_problems)
        _unused_disclosures(result, options)
        _check_held(result, reader, options, late, beside)
        _compare_trusted(result, options)
    except Exception as e:
        result['problems'].append(problem_from(e))
    read = result['entries']
    result['entries'] = [_answered(e, late, read) for e in read]
    result['summary'] = _summarise(result['entries'], result['problems'], sealed, result['held'])
    return {'result': result, 'state': state, 'beside': beside}


def fork_carried(carried, whole=False):
    """A book that carries on by itself from where this one stands, to try one
    more line: a stub or, with "whole", a line of any kind (_fork_reader). The
    book it was split from is left exactly as it was. Not part of the public
    interface."""
    out = _Carried()
    out.options = carried.options
    out.reader = _fork_reader(carried.reader, whole)
    out.any = carried.any
    out.closed = carried.closed
    out.failure = carried.failure
    return out


def promote_carried(carried):
    """A book that was split off to try a line takes the place of the one it
    was split from, which is not used again. From here on it reads any kind
    of entry. Not part of the public interface."""
    carried.reader.forked = False
    return carried


class Checker:
    """A checker that can be carried on. It reads a book once, keeps what it
    has worked out, and then takes more lines as the book grows, without
    reading the earlier lines again. Its answer for the book so far is the
    answer that check_book gives for the same text."""

    def __init__(self, text='', options=None, **named):
        self._carried = start_carried(fixed_options(options, **named))
        carry_on(self._carried, text)

    def add(self, more):
        """Take more whole lines, each ending with a line feed."""
        carry_on(self._carried, more)

    def result(self):
        """The answer for the book so far: a copy of its own each time, so that
        nothing done to an answer changes the checker."""
        return copy.deepcopy(answer_of(self._carried)['result'])


def open_checker(text='', options=None, **named):
    """A checker that can be carried on (see Checker). The options are read
    once, when the checker is opened, as check_book reads them, and fixed."""
    return Checker(text, options, **named)


def _disclosures_for(disclosures, index):
    """The disclosures handed over for one page, found as JavaScript finds a
    member by number: in an object by the number written as text, or in a
    list by its place."""
    if isinstance(disclosures, Mapping):
        for key in (index, str(index)):
            if key in disclosures:
                return disclosures[key]
        return None
    if isinstance(disclosures, list) and isinstance(index, int) and 0 <= index < len(disclosures):
        return disclosures[index]
    return None


def make_show(text, indexes, seal=None, disclosures=None):
    """Make a Show: some entries of a book, each with the proof that it is in the
    book (format description, section 11).

    indexes: which entries, counting from 0; at most 64. seal: the entry that
    is a seal to show the pages under: the Show is then of the book as it
    stood when that seal was made, and carries the seal and its time-stamps.
    disclosures: for covered fields, the disclosures to hand over with a
    page, by the page's index."""
    lines = _split_lines(text)
    seal_entry = None
    seal = _js.whole(seal)
    if seal is not None:
        if not isinstance(seal, int) or isinstance(seal, bool) or seal < 1 or seal >= len(lines):
            raise ValueError('there is no such entry')
        seal_entry = _js.parse(lines[seal])
        if not isinstance(seal_entry, dict) or 'seal' not in seal_entry:
            raise ValueError('that entry is not a seal')
        lines = lines[:seal]
    leaves = [utf8(line) for line in lines]
    wanted = sorted({_js.whole(i) for i in indexes})
    if len(wanted) < 1 or len(wanted) > MAX_PAGES:
        raise ValueError('a Show holds 1 to 64 pages')
    pages = []
    for index in wanted:
        path = inclusion_path(leaves, index)
        page = {'index': index, 'entry': lines[index], 'path': [to_base64url(p) for p in path]}
        reveal = _disclosures_for(disclosures, index)
        if _js.truthy(reveal):
            page['disclosures'] = reveal
        pages.append(page)
    show = {'type': 'provared.show.v0', 'size': len(lines), 'root': to_base64url(tree_root(leaves)), 'pages': pages}
    if seal_entry is not None:
        show['seal'] = seal_entry
    return show


def check_show(show, options=None, **named):
    """Check a Show.

    A Show can show a stub outside its slip (a wrong action, a wrong party, a
    wrong time, or a single stub over the limit). It cannot show that the
    agent stayed within a limit: that needs every stub under the slip.

    show: the Show, as a dict or as JSON text. Returns the same shape as
    check_book returns. A seal that comes with the Show is the last entry."""
    result = {'format': 'provared-show-draft-v0', 'size': 0, 'root': None, 'problems': [], 'notes': [], 'entries': [], 'held': [], 'summary': None}
    sealed = None
    options = fixed_options(options, **named)
    try:
        if isinstance(show, str):
            try:
                show = _js.parse(show)
            except ValueError:
                raise Refusal('not-json', 'The Show is not JSON.') from None
        _check_blocks_option(options)
        f.members(show, ['pages', 'root', 'size', 'type'], ['seal'], 'show')
        if show['type'] != 'provared.show.v0' or not isinstance(show['type'], str):
            raise f.fail('show.type', 'must be provared.show.v0.')
        f.whole_number(show['size'], 'show.size')
        if show['size'] < 1 or show['size'] > MAX_ENTRIES:
            raise f.fail('show.size', 'must be from 1 to 100,000.')
        f.fingerprint_text(show['root'], 'show.root')
        f.list_of(show['pages'], 1, MAX_PAGES, 'show.pages')
        result['size'] = show['size']
        result['root'] = show['root']
        root = from_base64url(show['root'])

        _compare_trusted(result, options)

        lines = []
        seen = set()
        for i, page in enumerate(show['pages']):
            f.members(page, ['entry', 'index', 'path'], ['disclosures'], f'pages[{i}]')
            if 'disclosures' in page:
                f.list_of(page['disclosures'], 1, 64, f'pages[{i}].disclosures')
            f.whole_number(page['index'], f'pages[{i}].index')
            if not isinstance(page['entry'], str) or _js.utf16_length(page['entry']) < 1 or _js.utf16_length(page['entry']) > MAX_LINE_BYTES:
                raise f.fail(f'pages[{i}].entry', 'must be one line of a book.')
            f.list_of(page['path'], 0, 64, f'pages[{i}].path')
            if page['index'] in seen:
                raise f.fail(f'pages[{i}].index', 'a page is repeated.')
            seen.add(page['index'])
            path = []
            for j, p in enumerate(page['path']):
                f.fingerprint_text(p, f'pages[{i}].path[{j}]')
                path.append(from_base64url(p))
            if not verify_inclusion(page['index'], show['size'], utf8(page['entry']), path, root):
                raise Refusal('proof-invalid', f"The proof for page {_js.number_text(page['index'])} does not lead to the top fingerprint.")
            lines.append((page['index'], page['entry'], page['disclosures'] if 'disclosures' in page else _UNDEFINED))
        lines.sort(key=lambda item: item[0])
        reader = _Reader(options, False)
        for index, line, disclosures in lines:
            _read_line(reader, index, line, disclosures)
        checked_ids = reader.ids
        stamp_floor = reader.seals['lastStampTime']
        result['entries'] = reader.entries
        result['problems'].extend(reader.handed_problems)
        _unused_disclosures(result, options)
        _compare_page_seals(result['entries'])

        # A seal that comes with the Show: the recorder's signature on exactly
        # this top fingerprint and this number of entries, and the outside
        # time-stamps on that seal.
        if 'seal' in show:
            entry = _new_entry(show['size'], 'seal')
            result['entries'].append(entry)
            try:
                f.members(show['seal'], ['seal'], ['stamps'], 'show.seal')
                # It is held to the pages as a seal in a whole book is held to the
                # entries before it: no unique number twice, and no block
                # time-stamp counted that states a time before a service's
                # time-stamp on a seal among the pages.
                fresh = {'count': 0, 'last': None, 'lastWhen': -INF, 'lastStampTime': stamp_floor, 'next': 0, 'sealed': None}
                _check_seal_entry(entry, show['seal'], fresh, checked_ids, options, None, [])
                entry['vouched'] = None
                if entry['content']['size'] != show['size'] or entry['content']['root'] != show['root']:
                    entry['problems'].append({'code': 'seal-mismatch', 'message': 'The seal that comes with the Show is for another book, or for this book at another length.'})
                # Against the seals among the pages, which all come before it in the book.
                _later_than_seals(entry, result['entries'])
                # The seal's own date against the pages it covers, as in a whole book.
                if _dated_before_covered(
                    nan_time(entry['content']['when']),
                    result['entries'],
                    len(result['entries']) - 1,
                    nan_time(entry['stampedAt']) if entry.get('stampedAt') else None,
                ):
                    entry['problems'].append({'code': 'time-went-backwards', 'message': 'This seal is dated before a page it covers. One of the two dates is not as it says.'})
            except Exception as e:
                entry['problems'].append(problem_from(e))
            if entry['problems']:
                entry['verified'] = 'none'
            elif entry.get('stampedAt'):
                time = nan_time(entry['stampedAt'])
                for page in result['entries']:
                    if page is not entry:
                        _credit_stamp(page, entry['stampedAt'], time)
                sealed = {'entries': show['size'], 'when': entry['stampedAt'], 'seal': show['size'], 'by': _counted_by(entry, stamp_floor)}
        if 'expectedRoot' not in options and not sealed:
            result['notes'].append('The top fingerprint was not compared with a copy you already trust, and no seal with a time-stamp from a service you trust comes with it.')
        elif 'expectedSize' not in options and not sealed:
            result['notes'].append('The number of entries was not compared with a number you already trust. The top fingerprint alone does not fix it.')
        result['notes'].append('Single pages cannot show whether the chain is whole, whether a limit was kept, or whether an approval was used only once. Those need every stub under the slip.')
        result['notes'].append('Single pages cannot show that a slip was not cancelled, or that a vouching record was not withdrawn, on a page that is not shown.')
        # An empty list is none, as for a whole book.
        if 'cancellations' in options and not (isinstance(options['cancellations'], list) and len(options['cancellations']) == 0):
            result['notes'].append(
                'Cancellations were handed over beside this Show. They were not used: single pages cannot show which stubs existed before a cancellation. Check the whole book with them.'
            )
    except Exception as e:
        result['problems'].append(problem_from(e))
    # An acknowledgement whose cancellation, among the pages, failed after the acknowledgement was read.
    for e in result['entries']:
        if e['kind'] != 'acknowledgement' or 'cancellation' not in e:
            continue
        named_entry = next((p for p in result['entries'] if p['index'] == e['cancellation']), None)
        if named_entry and named_entry['problems']:
            _fail_acknowledgement(e)
    # A seal or a cancellation that did not pass its check shows no time of its own.
    for e in result['entries']:
        if e['problems']:
            e.pop('stampedAt', None)
    result['summary'] = _summarise(result['entries'], result['problems'], sealed)
    return result
