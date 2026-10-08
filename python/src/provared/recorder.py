# The stub writer beside an agent. It keeps the agent's place in its chain,
# asks the check before acting (guard.py) before each action, and writes a
# stub for each action that is taken. It holds the book as text; where the
# text is kept is the caller's business.
#
# It makes the two things an agent's software must do into one call, so
# that they are not forgotten: ask first, and write the receipt after.
#
# One writer serves one chain: an agent under its slip, or a helper under
# its pass. Its calls wait for one another, so two actions asked for at the
# same moment (from two threads) are taken one after the other, each
# against the book as the one before left it. Two writers on copies of one
# book know nothing of each other: keeping them apart is the caller's
# business.
#
# The writer never puts into its book a line that would make the book fail
# its check. Before an action is taken, its stub is written and checked
# with the whole book; what the other side hands back is checked before it
# joins the stub, and left out if it does not check.
#
# The book is read once, when the writer is opened, and is then carried on
# (book.py): each new line is read by itself, against what was worked out
# from the lines before it. So no signature is checked twice, and what an
# action costs grows only slowly with the length of the book. Every line
# is tried on a reader split off the book's own, which takes the book's
# place only if the line is written, and is thrown away otherwise. So the
# book's own reader always stands for exactly the text of the book,
# whatever fails on the way.
#
# What is handed to the writer is copied when it is handed over: the
# request, the approval, what the other side hands back. The copy is what
# is checked and what is written, so a later change to the caller's own
# objects changes nothing.
#
# This is the Python version of the JavaScript library's src/recorder.js,
# ported one to one. Where JavaScript waits for a promise, this waits in
# the same thread: every call is an ordinary function. The other side's
# countersignature is asked for in a thread of its own, so that the time
# it is given can run out.

import concurrent.futures
import contextvars
import copy
import datetime
import inspect
import math
import re
import threading
from collections.abc import Mapping

from . import _js
from .book import _SNAKE, MAX_LINE_BYTES, answer_of, carry_on, check_countersignature, entry_line, fixed_options, fork_carried, latest_when, promote_carried, start_carried
from .encoding import Refusal, canonical_json, fingerprint, from_base64url, nan_time, now_ms, problem_from, utf8
from .guard import check_before_read
from .seal import CLOCK_ALLOWANCE_MS, MAX_STAMPS
from .standing import write_acknowledgement
from .stub import write_stub

COUNTERSIGN_WITHIN_MS = 30000
"""How long the other side is given to hand back its countersignature, unless the caller says otherwise: 30 seconds."""

# The longest wait a timer can hold in JavaScript, kept here so that both accept the same numbers.
_MAX_WAIT_MS = 2**31 - 1
# The most cancellations a check may be handed beside a book (book.py).
_MAX_HANDED = 16
# The deepest a copied value may nest: far more than a line of a book can hold.
_MAX_COPY_DEPTH = 64

_INSIDE_MESSAGE = 'The stub writer was called from inside an action it is taking. Call it once the action has ended.'


class _Absent:
    """What JavaScript calls undefined: a member that was not given. It is
    kept apart from None, which stands for null."""

    __slots__ = ()

    def __repr__(self):
        return 'ABSENT'


_ABSENT = _Absent()


def _member(value, name):
    """value[name] as JavaScript reads it from plain data: the member of an
    object, or nothing (undefined) for anything else."""
    if isinstance(value, dict) and name in value:
        return value[name]
    return _ABSENT


def _same(items, value):
    """Whether a list holds this very object (JavaScript's includes, for objects)."""
    return any(x is value for x in items)


# Where the platform can tell, a call to the writer made by an action that
# the writer is taking is refused at once. It would otherwise wait for the
# action to end, while the action waits for it. The mark is carried by the
# context, so it reaches the action's own code, and a thread started with
# a copy of that context.
_INSIDE = contextvars.ContextVar('provared_recorder_inside', default=None)


class _Mark:
    __slots__ = ('writer', 'running')

    def __init__(self, writer):
        self.writer = writer
        self.running = True


def _not_written(why):
    return Refusal('record-not-sound', why)


def _refuse_awaitable(value, why):
    """A function handed to the writer gave a coroutine or another
    awaitable. This library takes no part in asyncio: the awaitable is
    closed, unrun, and refused."""
    close = getattr(value, 'close', None)
    if callable(close):
        try:
            close()
        except Exception:
            pass
    raise TypeError(why)


# --- copies ---


# Stands in the list of an entry's members for a name that is not plain data.
_STRANGE = object()


def _scalar(value):
    return value is None or isinstance(value, (bool, int, float, str))


def _clone(value, most=_MAX_COPY_DEPTH, text_names=False):
    """A copy that nothing else holds, as structuredClone makes one, for plain
    data: objects (dicts, with text for names), lists, text, numbers, true,
    false and null. A value met twice is copied once. Raises TypeError for
    anything else (a function, an object of a class, bytes), and for a
    value that holds itself. It walks the value without recursion, so a
    deep value costs no stack. A name of a dict that is not text is taken
    as JavaScript would write it, or, with text_names, refused."""
    if _scalar(value) or value is _ABSENT:
        return value
    if not isinstance(value, (Mapping, list)):
        raise TypeError('not plain data')

    def fresh(v):
        if isinstance(v, Mapping):
            if text_names and not all(isinstance(k, str) for k in v):
                raise TypeError('a name that is not text')
            return {}, iter([(_js.property_key(k), item) for k, item in v.items()])
        return [], iter(list(v))

    memo = {}
    active = set()
    keep = [value]
    root, items = fresh(value)
    memo[id(value)] = root
    active.add(id(value))
    stack = [(value, root, items, 0)]
    while stack:
        source, made, items, depth = stack[-1]
        try:
            item = next(items)
        except StopIteration:
            stack.pop()
            active.discard(id(source))
            continue
        name, v = item if isinstance(made, dict) else (None, item)
        if _scalar(v):
            c = v
        elif isinstance(v, (Mapping, list)):
            if id(v) in active:
                raise TypeError('the value holds itself')
            c = memo.get(id(v))
            if c is None:
                # As deep as a copy may go: far more than a record holds. (The
                # connector for tools copies without a limit, as the JavaScript
                # one does, and refuses what nests too deeply itself.)
                if most is not None and depth + 1 > most:
                    raise TypeError('the value nests too deeply')
                c, inner = fresh(v)
                memo[id(v)] = c
                active.add(id(v))
                keep.append(v)
                stack.append((v, c, inner, depth + 1))
        else:
            raise TypeError('not plain data')
        if isinstance(made, dict):
            made[name] = c
        else:
            made.append(c)
    return root


def _plain(value, what):
    """A copy that nothing else holds."""
    try:
        return _clone(value)
    except Exception:
        raise Refusal('bad-field', f'{what} must be plain data: text, numbers, lists and objects.') from None


class _TooMuch(Exception):
    pass


def _copier():
    """A copy that nothing else holds, made in one pass: each member and each
    place is read once, and copied as it is read. A value met twice is
    copied once. Raises where it cannot be done: anything but plain data,
    a value that holds itself (which nests without end), or a value that,
    written out, would be longer than a line of a book may be.

    The copies one copier makes share one count, so that several values,
    each short enough for a line, cannot together cost more than a line."""
    copies = {}
    keep = []
    total = 0

    # The copy, and the fewest characters it takes written out: a text its
    # characters and two quotation marks; any other single value one; a list
    # or an object its brackets and commas, and each member's name with its
    # quotation marks and colon. A value met again is counted again, as it is
    # written out again.
    def walk(v, depth):
        if isinstance(v, str):
            return v, _js.utf16_length(v) + 2
        if v is None or isinstance(v, (bool, int, float)):
            return v, 1
        if not isinstance(v, (Mapping, list)):
            raise _TooMuch('not plain data')
        found = copies.get(id(v))
        if found is not None:
            return found
        if depth > _MAX_COPY_DEPTH:
            raise _TooMuch('the value nests too deeply, or holds itself')
        is_list = isinstance(v, list)
        if not is_list:
            try:
                v = {_js.property_key(k): item for k, item in v.items()}
            except TypeError:
                raise _TooMuch('not plain data') from None
        made = [] if is_list else {}
        size = 2
        members = 0
        for name, value in (enumerate(list(v)) if is_list else list(v.items())):
            item, count = walk(value, depth + 1)
            size += count + (1 if members > 0 else 0) + (0 if is_list else _js.utf16_length(name) + 3)
            members += 1
            if size > MAX_LINE_BYTES:
                raise _TooMuch('more than a line can hold')
            if is_list:
                made.append(item)
            else:
                made[name] = item
        copies[id(v)] = (made, size)
        keep.append(v)
        return made, size

    def copy_one(value):
        nonlocal total
        made, size = walk(value, 0)
        total += size
        if total > MAX_LINE_BYTES:
            raise _TooMuch('more than a line can hold')
        return made

    return copy_one


def _copy_of(value):
    return _copier()(value)


def _plain_held(held):
    """A copy of a cancellation given when the writer is opened, as plain
    data: its three members, and any other member, each copied. So what
    "cancellations" hands back is what was checked, and the writer never
    changes the caller's own object. One that cannot be copied so is
    refused when the writer is opened. Each of the three may be as long as
    a line; the other members share one line's length."""
    if not isinstance(held, dict):
        return held
    try:
        made = {}
        rest = _copier()
        for name, value in list(held.items()):
            known = name in ('cancellation', 'stamps', 'acknowledgements')
            made[name] = _copy_of(value) if known else rest(value)
        return made
    except Exception:
        raise Refusal('bad-field', 'options.cancellations: a copy of a cancellation could not be read as plain data.') from None


# --- times handed in ---

_MAX_TIME_MS = 8.64e15


def _time_clip(value):
    if not _js.finite(value) or abs(value) > _MAX_TIME_MS:
        return float('nan')
    # Towards zero, and never -0.
    return int(value) + 0


def _time_value(value):
    """A time handed in, as new Date(value).getTime() reads a number or a Date:
    milliseconds since 1970. A Python datetime with a time zone stands for a
    Date. Text, True, a datetime with no time zone or anything else would be
    read by rules that differ from one device to another (text with no time
    zone is taken as local time), so they are refused, as in the JavaScript
    library."""
    if _js.is_number(value):
        return _time_clip(value)
    if isinstance(value, datetime.datetime) and value.tzinfo is not None:
        epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        return _time_clip((value - epoch) // datetime.timedelta(milliseconds=1))
    raise Refusal('bad-field', 'when: must be a number of milliseconds, or a Date.')


# --- the writer ---


def open_recorder(book, slip, private_keys, issuer_keys, pass_=None, options=None, now=None, countersign_within=COUNTERSIGN_WITHIN_MS):
    """Open the stub writer for one agent under one slip.

    book: the book so far, as text: at least the slip.
    slip: the fingerprint of the slip.
    private_keys: the agent's private keys, Ed25519 then ML-DSA-87.
    issuer_keys: the thumbprints of the passkeys this agent's software
    trusts; a slip from any other key allows nothing.
    pass_: for a helper agent, the fingerprint of the pass it acts under.
    options: further options for the checker, named as in the JavaScript
    library (sealKeys, stampServices, blocks, vouchers, cancellations,
    withoutMethods). They are read once, as a whole check reads them, and
    fixed.
    now: the clock, a function that gives milliseconds since 1970; the
    device's by default. "act" takes an action at the clock's time, and
    nothing is written that is dated more than 300 seconds ahead of it.
    countersign_within: how long the other side is given to countersign,
    in milliseconds; 30,000 by default.

    Returns the writer (a Recorder). Raises a Refusal, "record-not-sound",
    if the book so far has a problem."""
    return Recorder(book, slip, private_keys, issuer_keys, pass_, options, now, countersign_within)


class Recorder:
    """The stub writer for one agent under one slip: before, record, act,
    book, check, cancellations, add. Made by open_recorder."""

    def __init__(self, book, slip, private_keys, issuer_keys, pass_=None, options=None, now=None, countersign_within=COUNTERSIGN_WITHIN_MS):
        if now is None:
            now = now_ms
        if not callable(now):
            raise Refusal('bad-field', 'now: must be a function that gives the time in milliseconds.')
        # A clock that gives anything but a time is a clock that failed: no comparison with it would hold.
        device = now

        def clock():
            time = device()
            if not _js.finite(time):
                raise Refusal('bad-field', 'now: the clock did not give a time in milliseconds.')
            return time

        self._now = clock
        if not (_js.finite(countersign_within) and 1 <= countersign_within <= _MAX_WAIT_MS):
            raise Refusal('bad-field', 'countersignWithin: must be a number of milliseconds from 1 to 2,147,483,647.')
        self._within = countersign_within
        self._slip = slip
        self._pass = pass_
        self._private_keys = private_keys
        # Whom the writer trusts is fixed when it is opened: read once, as a
        # whole check reads it, and copied. The passkeys it trusts are its
        # own "issuer_keys", whatever the options say, read through the
        # same fixed copy.
        # (The options may also be named in Python's way, "stamp_services", as for check_book.)
        named = {name: value for name, value in options.items() if name in _SNAKE and name != 'issuer_keys'} if isinstance(options, Mapping) else {}
        fixed = fixed_options(options, **named)
        own = fixed_options({'issuerKeys': issuer_keys} if issuer_keys is not None else {})
        try:
            base = {}
            for name, value in fixed.items():
                if name != 'issuerKeys':
                    base[name] = value
            base.update(own)
            # A list longer than a check accepts is refused by the check; it is not walked through here.
            cancellations = base.get('cancellations')
            if isinstance(cancellations, list) and len(cancellations) <= _MAX_HANDED:
                base['cancellations'] = [_plain_held(c) for c in cancellations]
        except Refusal:
            raise
        except Exception:
            raise Refusal('bad-field', 'options: a member could not be read.') from None
        self._base = base
        # The person's cancellations that the writer holds beside its book:
        # those given when it was opened, and those of its own slip that
        # were handed to it since and could not yet be written into the
        # book ("kept"). A cancellation of another slip that cannot be added
        # is nothing to this writer and is not kept, so no number of them
        # can crowd out one that matters. Each is written into the book as
        # soon as it can be (_write_waiting). Until then it lives only in
        # this writer: "cancellations" hands it back, so that the caller can
        # keep it with the book. A check may be handed 16 at most: see
        # _beside.
        self._given = base['cancellations'] if isinstance(base.get('cancellations'), list) else []
        self._kept = []
        # Those given at opening that the book does not hold: written into it as the kept ones are.
        self._unwritten = []
        # The copies given at opening that already hold an acknowledgement
        # of this writer's own agent: the writer puts no second one with them.
        self._own_acked = []
        # Whether the person's cancellation of this writer's slip was handed
        # to it. From then on it takes no action, whatever becomes of the
        # cancellation itself.
        self._stopped = False
        # The acknowledgements that this writer's own agent has signed, by
        # the fingerprint of the cancellation each is for: those the book
        # holds ("written"), and those signed since the writer was opened.
        # One cancellation is acknowledged once.
        self._acknowledged = {}
        self._written = set()
        # Those that could not yet follow their cancellation into the book,
        # by the fingerprint of the cancellation, with the cancellation itself.
        self._waiting = {}
        without = base.get('withoutMethods')
        self._without = without if isinstance(without, list) else []
        self._text = book + '\n' if isinstance(book, str) and book != '' and not book.endswith('\n') else book

        # One call at a time, from any thread. The answer to "would this be
        # outside the slip?" holds only until the next stub is written.
        self._lock = threading.Lock()
        self._owner = None

        # The book is read once, here. "_carried" always stands for exactly
        # the text of the book: every line that joins the text is read into it.
        self._carried = start_carried(base)
        carry_on(self._carried, self._text)
        result = self._standing()['result']
        if result['summary']['problemFound']:
            raise _not_written('A problem was found in the record so far. It must be looked at before the agent acts again.')
        self._after = self._last_stub(result['entries'])
        # What was given at opening: the first sound acknowledgement of this
        # writer's own agent that came with a cancellation is the one it
        # goes on handing back; a cancellation that the book does not hold
        # waits to be written.
        given = self._given
        for i, h in enumerate(result['held']):
            if not h['used']:
                continue
            # The person's cancellation of this writer's own slip, given when it was opened, stops it from the start.
            if h['slip'] == slip:
                self._stopped = True
            for j, a in enumerate(h['acknowledgements']):
                if a['state'] != 'valid' or h['slip'] != slip or a['pass'] != pass_:
                    continue
                if not _same(self._own_acked, given[i]):
                    self._own_acked.append(given[i])
                if h['fingerprint'] not in self._acknowledged:
                    self._acknowledged[h['fingerprint']] = given[i]['acknowledgements'][j]
            if h['inBook'] is None:
                self._unwritten.append({'entry': given[i], 'slip': h['slip'], 'when': nan_time(h['content']['when']), 'fingerprint': h['fingerprint'], 'tried': False})
        # The first acknowledgement of this writer's own agent that the book
        # holds for a cancellation is the one it goes on handing back.
        lines = self._text.split('\n') if isinstance(self._text, str) else []
        for e in result['entries']:
            if e['kind'] != 'acknowledgement' or e['problems'] or e.get('slip') != slip or e.get('pass') != pass_:
                continue
            if e['content']['cancellation'] in self._written:
                continue
            self._acknowledged[e['content']['cancellation']] = _js.parse(lines[e['index']])['acknowledgement']
            self._written.add(e['content']['cancellation'])
        # An acknowledgement given at opening, for a cancellation that the
        # book holds without it, follows the cancellation into the book: it
        # was still waiting when the writer that signed it handed it back.
        for i, h in enumerate(result['held']):
            if h['used'] and h['slip'] == slip and h['inBook'] is not None and h['fingerprint'] in self._acknowledged and h['fingerprint'] not in self._written:
                self._waiting[h['fingerprint']] = given[i]['cancellation']
        # The services the slip names, to check a countersignature before it goes into the book.
        slip_entry = next((e for e in result['entries'] if e['kind'] == 'slip' and e['fingerprint'] == slip), None)
        self._services = slip_entry['content']['with'] if slip_entry and slip_entry.get('content') else []

    # --- what the writer holds beside its book ---
    #
    # An acknowledgement that waits to follow its cancellation into the book
    # is handed back too, with the cancellation, unless a copy given at
    # opening already carries it. So a writer opened again from what this
    # one hands back writes the same acknowledgement, not a second one.
    # What the writer holds beside its book, the most needed first: the
    # person's cancellations of its own slip that the book does not hold
    # (those kept, then those given at opening), which stop the writer;
    # then the acknowledgements that wait, in the order in which they began
    # to wait (each carried by a copy given at opening, or handed back by
    # itself); then every other copy given at opening. A check may be
    # handed sixteen at most: where there are more, the last give way, so
    # that copies of other slips, or of cancellations the book holds, can
    # never crowd out one that matters.

    def _own_unwritten(self):
        return [u['entry'] for u in self._unwritten if u['slip'] == self._slip]

    def _waiting_part(self, own=None):
        if own is None:
            own = self._own_unwritten()
        part = []
        for cancellation, record in self._waiting.items():
            carriers = [g for g in self._given if _js.truthy(g) and _js.truthy(_member(g, 'cancellation')) and _member(g['cancellation'], 'payload') == _member(record, 'payload')]
            if not carriers:
                part.append({'cancellation': record, 'acknowledgements': [self._acknowledged.get(cancellation)]})
            for g in carriers:
                if not _same(own, g) and not _same(part, g):
                    part.append(g)
        return part

    def _room(self):
        own = self._own_unwritten()
        return _MAX_HANDED - len(self._kept) - len(own) - len(self._waiting_part(own))

    def _beside(self):
        if not self._kept and not self._waiting:
            return self._given
        own = self._own_unwritten()
        waits = self._waiting_part(own)
        rest = [g for g in self._given if not _same(own, g) and not _same(waits, g)]
        return ([k['entry'] for k in self._kept] + own + waits + rest)[:_MAX_HANDED]

    def _checking(self):
        return {**self._base, 'cancellations': self._beside()} if self._kept or self._waiting else self._base

    def _while_stopped(self, answer):
        if self._stopped and answer['allowed']:
            answer['allowed'] = False
            answer['breaches'].append({'code': 'after-cancellation', 'message': 'The person cancelled the slip: the cancellation was handed to this stub writer.'})
        return answer

    # Where the agent's own chain stands: the last stub under this slip, and
    # under this pass if it acts under one.
    def _last_stub(self, entries):
        last = None
        for e in entries:
            if e['kind'] == 'stub' and e.get('slip') == self._slip and e.get('pass') == self._pass:
                last = {'seq': e['content']['seq'], 'fingerprint': e['fingerprint']}
        return last

    # The answer for the book as it stands, or for a reader split off it, with the cancellations held beside the book.
    def _standing(self, of=None):
        return answer_of(self._carried if of is None else of, self._checking())

    # --- one call at a time ---

    def _in_turn(self, work):
        mark = _INSIDE.get()
        if (mark is not None and mark.writer is self and mark.running) or self._owner == threading.get_ident():
            raise RuntimeError(_INSIDE_MESSAGE)
        with self._lock:
            self._owner = threading.get_ident()
            try:
                return work()
            finally:
                self._owner = None

    # What the caller hands in to be run (the action) is run under a mark,
    # so that a call to the writer from inside it is caught. The mark holds
    # only while the writer is waiting for that work.
    def _run_inside(self, perform):
        mark = _Mark(self)
        token = _INSIDE.set(mark)
        try:
            value = perform()
        finally:
            mark.running = False
            _INSIDE.reset(token)
        if inspect.isawaitable(value):
            _refuse_awaitable(value, 'perform: the action must be an ordinary function that takes the action and gives its result. It gave a coroutine, which was not run.')
        return value

    # The other side is asked in a thread of its own, under the same mark,
    # and given "countersign_within" milliseconds to answer. After that the
    # writer goes on, the mark no longer holds, and whatever the function
    # gives later is not used.
    def _ask_other_side(self, countersign, stub):
        mark = _Mark(self)
        context = contextvars.copy_context()
        context.run(_INSIDE.set, mark)
        answer = concurrent.futures.Future()

        def job():
            try:
                value = countersign(stub)
                if inspect.isawaitable(value):
                    _refuse_awaitable(value, 'countersign: must be an ordinary function that gives the countersignature, or None. It gave a coroutine, which was not run.')
                answer.set_result(value)
            except Exception as e:  # handed on to the writer, which decides
                answer.set_exception(e)
            except BaseException as e:  # noqa: BLE001
                # SystemExit, KeyboardInterrupt and the like, raised by the other side's
                # function in its own thread, are a failure like any other: the stub
                # stands one-sided.
                answer.set_exception(RuntimeError(f'the countersign function raised {type(e).__name__}'))

        threading.Thread(target=context.run, args=(job,), daemon=True, name='provared-countersign').start()
        try:
            return answer.result(timeout=self._within / 1000)
        except concurrent.futures.TimeoutError:
            raise RuntimeError('no answer in time') from None
        finally:
            mark.running = False

    # What a call hands in, copied at the moment of the call.
    def _asked(self, request, more):
        if request is None or _scalar(request) or isinstance(request, bytes):
            raise Refusal('bad-field', 'The request must be an object.')
        if not isinstance(more, dict):
            more = {}
        call = {
            'request': _plain(request, 'The request'),
            'when': _ABSENT if more.get('when') is None else _time_value(more['when']),
            'terms': more.get('terms', _ABSENT),
            'countersign': more.get('countersign', _ABSENT),
            'hasApproval': more.get('approval') is not None,
            'approval': _ABSENT,
        }
        if call['hasApproval']:
            try:
                call['approval'] = _clone(_member(more['approval'], 'record'))
            except Exception:
                call['approval'] = _ABSENT  # not a record: refused when the stub is written
        return call

    def _calling(self, request, more, work):
        call = self._asked(request, more)
        return self._in_turn(lambda: work(call))

    def _proposal_from(self, call, when):
        request = call['request']
        if not isinstance(request, dict):
            request = {}
        proposal = {'slip': self._slip, 'action': request.get('action')}
        for name in ('amount', 'with', 'details'):
            # An empty list of documents is the same as none, as the stub itself is written.
            if name == 'details' and isinstance(request.get('details'), list) and len(request['details']) == 0:
                continue
            if name in request:
                proposal[name] = request[name]
        if _js.truthy(self._pass):
            proposal['pass'] = self._pass
        proposal['when'] = when
        if call['terms'] is not _ABSENT:
            proposal['terms'] = call['terms']
        if call['hasApproval'] and call['approval'] is not _ABSENT:
            proposal['approval'] = call['approval']
        return proposal

    def _ahead_of_clock(self, when):
        return when > self._now() + CLOCK_ALLOWANCE_MS

    def _behind_clock(self, when):
        return when < self._now() - CLOCK_ALLOWANCE_MS

    # The stub for an action, checked with the whole book before anything is
    # done with it. Nothing on its line may be dated ahead of the clock: the
    # stub's own date is looked at before this, and the approval's here. It
    # is read by a reader split off the book's own, which is handed back: if
    # the stub is not written after all, that reader is simply not used.
    def _fits_book(self, made, otherwise):
        tried = fork_carried(self._carried)
        carry_on(tried, made['line'] + '\n')
        checked = self._standing(tried)['result']
        if checked['summary']['problemFound']:
            raise _not_written(otherwise)
        if latest_when(checked['entries'][-1]) > self._now() + CLOCK_ALLOWANCE_MS:
            raise _not_written('The approval that goes with this action is dated ahead of the clock, so nothing was written.')
        return tried

    # The fingerprint of an approval is worked out here, from the record
    # itself. One handed over with it is not relied on.
    @staticmethod
    def _approval_fingerprint(record):
        try:
            return fingerprint(from_base64url(record['payload']))
        except Exception:
            raise Refusal('approval-invalid', 'The approval handed over is not a signed record.') from None

    # The stub for an action, with the approval that goes with it, as a line.
    def _compose_stub(self, call, when):
        request = call['request'] if isinstance(call['request'], dict) else {}
        approval = self._approval_fingerprint(call['approval']) if call['hasApproval'] else None
        stub = write_stub(
            {
                'slip': self._slip,
                'after': self._after,
                'action': request.get('action'),
                'amount': request.get('amount'),
                'with': request.get('with'),
                'details': request.get('details'),
                'approval': approval,
                'terms': None if call['terms'] is _ABSENT else call['terms'],
                'pass': self._pass,
                'when': when,
            },
            self._private_keys,
        )
        entry = {'stub': stub['record']}
        if call['hasApproval']:
            entry['approval'] = call['approval']
        line = entry_line(entry)
        if len(utf8(line)) > MAX_LINE_BYTES:
            raise Refusal('too-large', 'The record of this action is longer than a line of a book may be.')
        return {'stub': stub, 'entry': entry, 'line': line, 'countersignature': {'accepted': False, 'problem': None}}

    # Ask the other side for its countersignature, and put it with the stub
    # if it checks: the right keys, the right stub, not dated ahead of the
    # clock, and a line that still fits. One that does not check is left
    # out, and the stub stands one-sided, which is what happened.
    def _countersigned(self, made, call):
        if not callable(call['countersign']):
            return made
        countersignature = {'accepted': False, 'problem': None}
        line = made['line']
        try:
            # The other side is handed a copy: nothing it does to it changes the stub.
            given = self._ask_other_side(call['countersign'], copy.deepcopy(made['stub']['record']))
            if _js.truthy(given):
                # What it hands back is copied at once. The copy is what is checked, and what joins the stub.
                try:
                    kept = _clone(given)
                except Exception:
                    raise Refusal('countersignature-invalid', 'What the other side handed back is not a signed record.') from None
                w = _member(call['request'], 'with')
                service = next((s for s in self._services if s.get('id') == w), None) if isinstance(w, str) else None
                checked = check_countersignature(kept, made['stub']['fingerprint'], service, self._without)
                if checked['state'] != 'valid':
                    raise Refusal('countersignature-invalid', 'This device could not check the countersignature.')
                if nan_time(checked['when']) > self._now() + CLOCK_ALLOWANCE_MS:
                    raise Refusal('countersignature-invalid', 'The countersignature is dated ahead of the clock.')
                with_it = entry_line({**made['entry'], 'countersignature': kept})
                if len(utf8(with_it)) > MAX_LINE_BYTES:
                    raise Refusal('too-large', 'With the countersignature, the line would be longer than a line of a book may be.')
                line = with_it
                countersignature['accepted'] = True
        except Exception as e:
            countersignature['problem'] = (
                problem_from(e) if isinstance(e, Refusal) else {'code': 'countersignature-missing', 'message': 'Asking the other side for its countersignature failed, or took too long.'}
            )
        return {**made, 'line': line, 'countersignature': countersignature}

    # The line joins the book. The reader that takes the book's place is
    # the one the stub was tried on, if the line is still the one tried.
    # With a countersignature the line is another: it is read from where
    # the book stood, and the reader that tried the stub alone is not used.
    def _commit(self, composed, made, tried):
        following = tried
        if composed['line'] != made['line']:
            following = fork_carried(self._carried)
            carry_on(following, composed['line'] + '\n')
        self._carried = promote_carried(following)
        self._text += composed['line'] + '\n'
        stub = composed['stub']
        self._after = {'seq': stub['seq'], 'fingerprint': stub['fingerprint']}
        return {**stub, 'line': composed['line'], 'countersignature': composed['countersignature']}

    # A line that someone else made is tried on a reader split off the
    # book's own, which may read a line of any kind. If the book passes its
    # check with the line, and the line is not dated ahead of the clock,
    # that reader takes the book's place and the line joins the text.
    # Otherwise it is thrown away, and the book's own reader is as it was.
    # "at" is the clock, read once by the caller.
    def _take_line(self, line, at, options=None):
        if options is None:
            options = self._checking()
        tried = fork_carried(self._carried, True)
        carry_on(tried, line + '\n')
        checked = answer_of(tried, options)['result']
        if checked['summary']['problemFound']:
            return {'fits': False, 'ahead': False, 'why': 'with it, the book would not pass its check.'}
        if latest_when(checked['entries'][-1]) > at + CLOCK_ALLOWANCE_MS:
            return {'fits': False, 'ahead': True, 'why': 'it is dated ahead of the clock.'}
        self._carried = promote_carried(tried)
        self._text += line + '\n'
        return {'fits': True, 'checked': checked}

    # A cancellation held beside the book is written into the book as soon
    # as it can be: once the date it gives is no longer ahead of the clock.
    # It goes in as the entry it is, without the acknowledgements that came
    # with it. If the book would not pass its check with it even then, it
    # is not tried again, and the writer goes on holding it.
    def _write_waiting(self, at):
        for items in (self._kept, self._unwritten):
            for item in list(items):
                if item['tried'] or item['when'] > at + CLOCK_ALLOWANCE_MS:
                    continue
                entry = {'cancellation': item['entry']['cancellation']}
                if 'stamps' in item['entry']:
                    entry['stamps'] = item['entry']['stamps']
                taken = self._take_line(entry_line(entry), at)
                if not taken['fits']:
                    item['tried'] = True
                    continue
                # In the book, it is no longer one that waits.
                for k, x in enumerate(items):
                    if x is item:
                        del items[k]
                        break
                # The acknowledgement that was signed when it was handed over follows it into the book.
                if item['fingerprint'] in self._acknowledged:
                    self._acknowledge(item['fingerprint'], item['entry']['cancellation'], True, at)
        # An acknowledgement that could not follow its cancellation into the
        # book, because it was dated ahead of the clock, is tried again.
        for cancellation in list(self._waiting):
            taken = self._take_line(entry_line({'acknowledgement': self._acknowledged.get(cancellation)}), at)
            if taken['fits']:
                self._written.add(cancellation)
            if taken['fits'] or not taken['ahead']:
                self._waiting.pop(cancellation, None)

    # The acknowledgement goes with the cancellation that the writer holds
    # beside its book, so that "cancellations" hands the two back together.
    # A copy holds four at most. The writer's own is always kept: where the
    # copy already holds four, the last of the others gives way to it.
    # Another agent's is put with the copy only where there is room.
    def _put_with(self, entry, record, own=True):
        if not _js.truthy(record):
            return
        items = entry['acknowledgements'] if isinstance(entry.get('acknowledgements'), list) else []
        if any(_js.truthy(a) and _member(a, 'payload') == _member(record, 'payload') for a in items):
            return
        # A copy given at opening that already holds one of the agent's own takes no second one.
        if own and _same(self._own_acked, entry):
            return
        if len(items) >= 4:
            if not own:
                return
            items = items[:3]
        entry['acknowledgements'] = [*items, copy.deepcopy(record)]

    # The agent's side says that it was handed the person's cancellation of
    # its slip, and when: signed with this writer's own keys, once for each
    # cancellation, and dated by the writer's clock. Where the book holds
    # the cancellation, the acknowledgement follows it into the book. It is
    # handed back to the caller, to be given to the person. If it cannot be
    # signed, or does not check (the writer was opened with keys that are
    # not the agent's), there is none; the cancellation stops the writer all
    # the same.
    #
    # It is not dated before the writer's own last stub, nor before a pass
    # that its agent handed on. Either may be dated up to 300 seconds ahead
    # of the clock, and the agent was not told before it made them: an
    # acknowledgement dated by the clock alone would have them read as made
    # after the agent was told.
    def _acknowledge(self, cancellation, cancellation_record, in_book, at):
        record = self._acknowledged.get(cancellation)
        if not _js.truthy(record):
            when = at
            for e in self._standing()['result']['entries']:
                if e.get('slip') != self._slip or not _js.truthy(e.get('content')):
                    continue
                content = e['content']
                own = (e['kind'] == 'stub' and e.get('pass') == self._pass) or (e['kind'] == 'pass' and (content['from'] if 'from' in content else None) == self._pass)
                if own and nan_time(content['when']) > when:
                    when = nan_time(content['when'])
            try:
                made = write_acknowledgement({'slip': self._slip, 'cancellation': cancellation, 'pass': self._pass, 'when': when}, self._private_keys)['record']
            except Exception:
                return None
            # Checked as a reader will check it, beside the person's own copy of the cancellation.
            held = answer_of(self._carried, {**self._base, 'cancellations': [{'cancellation': cancellation_record, 'acknowledgements': [made]}]})['result']['held']
            beside = held[0] if held else None
            if not beside or len(beside['acknowledgements']) != 1 or beside['acknowledgements'][0]['state'] != 'valid':
                return None
            record = made
            self._acknowledged[cancellation] = record
        if in_book and cancellation not in self._written:
            taken = self._take_line(entry_line({'acknowledgement': record}), at)
            if taken['fits']:
                self._written.add(cancellation)
            elif taken['ahead']:
                self._waiting[cancellation] = cancellation_record
        # It goes with the cancellation wherever the writer holds that beside its book.
        held = next((k for k in self._kept if k['fingerprint'] == cancellation), None)
        if held:
            self._put_with(held['entry'], record)
        opened = next(
            (h for h in self._given if _js.truthy(h) and _js.truthy(_member(h, 'cancellation')) and _member(h['cancellation'], 'payload') == _member(cancellation_record, 'payload')),
            None,
        )
        if opened:
            self._put_with(opened, record)
        return copy.deepcopy(record)

    @staticmethod
    def _refused(message, acknowledgement=None):
        e = _not_written(message)
        if _js.truthy(acknowledgement):
            e.acknowledgement = acknowledgement
        return e

    # The acknowledgements handed over with the person's cancellation of
    # this writer's slip. Each is checked by itself, so that one which does
    # not check is never taken for one which does. The first sound one of
    # this writer's own agent is the one the writer goes on handing back,
    # unless it already has one; any further one of its own agent is let
    # go, so that a copy never holds two. The sound ones of other agents are
    # handed back, to stay with the copy. At most sixteen are looked at.
    def _sort_handed(self, cancellation, cancellation_record, handed):
        others = []
        if not isinstance(handed, list):
            return others
        for record in handed[:_MAX_HANDED]:
            held = answer_of(self._carried, {**self._base, 'cancellations': [{'cancellation': cancellation_record, 'acknowledgements': [record]}]})['result']['held']
            beside = held[0] if held else None
            if not beside or not beside['used'] or len(beside['acknowledgements']) != 1 or beside['acknowledgements'][0]['state'] != 'valid':
                continue
            if beside['acknowledgements'][0]['pass'] != self._pass:
                others.append(record)
            elif cancellation not in self._acknowledged:
                self._acknowledged[cancellation] = record
        return others

    # The writer's own acknowledgement, and the sound ones of other agents, go with a copy the writer holds.
    def _put_handed(self, entry, cancellation, others):
        self._put_with(entry, self._acknowledged.get(cancellation))
        for other in others:
            self._put_with(entry, other, False)

    # The time-stamps that a cancellation should go with: those a copy of it
    # already holds, and those handed over now, none twice. Each is judged
    # by itself, beside the book: one with which the cancellation does not
    # pass its check is left out. Those that this writer counts come first,
    # then the others, four at most, so that a time-stamp the writer counts
    # is never crowded out by one it does not. Only a set with which the
    # book still passes its check is taken. None where nothing changes.
    def _merged_stamps(self, cancellation_record, holds, offered):
        def key_of(s):
            try:
                return canonical_json(s)
            except Exception:
                return None

        held = {key_of(s) for s in holds}
        every = list(holds)
        for s in offered:
            key = key_of(s)
            if key is None or key in held:
                continue
            held.add(key)
            every.append(s)
        if len(every) == len(holds):
            return None
        counted = []
        uncounted = []
        for s in every:
            found = answer_of(self._carried, {**self._base, 'cancellations': [{'cancellation': cancellation_record, 'stamps': [s]}]})['result']['held']
            one = found[0] if found else None
            if not one or not one['used'] or one['problems']:
                continue
            if _js.truthy(one.get('stampedAt')):
                counted.append((s, nan_time(one['stampedAt'])))
            else:
                uncounted.append(s)
        # Of those it counts, the earliest come first: they place the cancellation earliest in time.
        counted.sort(key=lambda c: c[1])
        stamps = ([c[0] for c in counted] + uncounted)[:MAX_STAMPS]
        if len(stamps) == 0 or key_of(stamps) == key_of(holds):
            return None
        try:
            form = entry_line({'cancellation': cancellation_record, 'stamps': stamps})
        except Exception:
            return None
        tried = fork_carried(self._carried, True)
        carry_on(tried, form + '\n')
        if answer_of(tried, self._checking())['result']['summary']['problemFound']:
            return None
        return stamps

    # --- the calls ---

    def before(self, request, more=None):
        """Ask whether an action would be outside the slip. Nothing is
        written. The answer holds only until the next stub is written: use
        "act" to ask and act in one step.

        request: {"action", and where they apply "amount", "with", "details"}.
        more: {"when" (milliseconds since 1970, or a datetime), "terms",
        "approval": {"record"}}.
        Returns {"allowed", "problems", "breaches", "needs"}."""

        def work(call):
            proposal = self._proposal_from(call, call['when'] if call['when'] is not _ABSENT else self._now())
            return self._while_stopped(check_before_read(lambda: self._standing(), proposal, self._checking()))

        return self._calling(request, more, work)

    def record(self, request, more=None):
        """Write the stub for an action that was taken, and add it to the
        book. It does not ask first: use "act" for that. An action that was
        taken is recorded whether or not it was inside the slip, because
        the record is of what happened. But a stub is written only if the
        book still passes its check with it: one dated ahead of the clock,
        or before the stub ahead of it, or with an approval that does not
        fit, is refused, and nothing is written. The other side is asked to
        countersign only once the stub has passed that check, so a stub
        that is refused has gone nowhere.

        more: "when" (when the action was taken; the clock by default),
        "terms" (the fingerprint of the service's terms relied on),
        "approval" ({"record": the person's signed approval of this
        action}), "countersign" (a function that asks the other side for
        its countersignature of the stub it is handed, and gives it, or
        None if it gives none).
        Returns {"record", "fingerprint", "seq", "line", "countersignature":
        {"accepted", "problem"}}. "countersignature.accepted" says whether a
        countersignature was given, checked and put with the stub. Where
        one was given and did not check, or asking for it failed, "problem"
        says why, and the stub is one-sided.
        Raises a Refusal, "record-not-sound", if the book would not pass its
        check with the stub; nothing is written."""

        def work(call):
            self._write_waiting(self._now())
            when = call['when'] if call['when'] is not _ABSENT else self._now()
            if self._ahead_of_clock(when):
                raise _not_written('The stub was not written: it is dated ahead of the clock.')
            made = self._compose_stub(call, when)
            tried = self._fits_book(made, 'The stub was not written: with it, the book would not pass its check.')
            return self._commit(self._countersigned(made, call), made, tried)

        return self._calling(request, more, work)

    def act(self, request, perform, more=None):
        """Ask first; if the action is allowed, take it and write its stub.

        If the action is not allowed it is not taken and nothing is
        written. The action is taken now: a date handed in ("when") must be
        within 300 seconds of the writer's clock, or the action is not
        taken. Before the action is taken, its stub is written and checked
        with the whole book, so that the receipt is known to fit before
        there is anything to give a receipt for. Where the slip asks for a
        countersignature, the action is taken only if a way to ask for one
        ("countersign") is given. If taking the action fails with an error,
        the error is passed on and no stub is written: there is then no
        receipt for whatever part of the action did happen, and the caller
        must deal with that. If taking the action never ends, the writer
        waits: it cannot know what happened.

        perform: a function of no arguments that takes the action and gives
        its result. It must not call this writer: such a call is refused at
        once. It must be an ordinary function, not a coroutine function.
        more: as for "record"; "when" defaults to the clock and must be
        within 300 seconds of it.
        Returns {"done", "answer"} and, where the action was taken,
        "result" (what perform gave) and "stub" (as "record" gives it)."""

        def work(call):
            self._write_waiting(self._now())
            when = call['when'] if call['when'] is not _ABSENT else self._now()
            answer = self._while_stopped(check_before_read(lambda: self._standing(), self._proposal_from(call, when), self._checking()))

            def stop(problem):
                answer['allowed'] = False
                answer['problems'].append(problem)

            if answer['allowed'] and self._ahead_of_clock(when):
                stop({'code': 'record-not-sound', 'message': 'The action is dated ahead of the clock.'})
            if answer['allowed'] and self._behind_clock(when):
                stop({
                    'code': 'record-not-sound',
                    'message': 'The action is dated behind the clock. An action is taken now, so its date may not be more than 300 seconds before the stub writer\'s clock. '
                    'An action that was taken earlier is written with "record".',
                })
            # Said whether or not something else stands in the way too, so that whoever reads the answer sees all of it.
            if 'countersignature' in answer['needs'] and not callable(call['countersign']) and not any(b['code'] == 'countersignature-missing' for b in answer['breaches']):
                answer['allowed'] = False
                answer['breaches'].append({
                    'code': 'countersignature-missing',
                    'message': 'The slip asks for the other side to countersign this action, and the stub writer was given no way to ask for a countersignature.',
                })
            made = None
            tried = None
            if answer['allowed']:
                try:
                    made = self._compose_stub(call, when)
                    tried = self._fits_book(made, 'The stub for this action would not pass the check of the book, so the action was not taken.')
                except Exception as e:
                    stop(problem_from(e))
            if not answer['allowed']:
                return {'done': False, 'answer': answer}
            outcome = self._run_inside(perform)
            stub = self._commit(self._countersigned(made, call), made, tried)
            return {'done': True, 'answer': answer, 'result': outcome, 'stub': stub}

        return self._calling(request, more, work)

    def book(self):
        """The book as it now stands. To keep the book and the cancellations the
        writer holds beside it together, read both with snapshot()."""
        return self._text

    def snapshot(self):
        """The book and the cancellations the writer holds beside it, read
        together, so that nothing another thread does falls between the two:
        (book, cancellations). From another thread it waits for a call in
        progress; from inside an action the writer is taking, it reads at once."""
        return self._quietly(lambda: (self._text, copy.deepcopy(self._beside())))

    def _quietly(self, read):
        """Read the writer's state: at once from inside its own call, where
        nothing else can change it; otherwise once no call is in progress."""
        mark = _INSIDE.get()
        if (mark is not None and mark.writer is self and mark.running) or self._owner == threading.get_ident():
            return read()
        with self._lock:
            return read()

    def check(self):
        """What the record shows as it stands: the answer that a whole check
        of the book gives, with the cancellations the writer holds beside
        it. Nothing is read again. A copy of its own each time."""
        return self._in_turn(lambda: copy.deepcopy(self._standing()['result']))

    def cancellations(self):
        """The person's cancellations that the writer holds beside its book:
        those it was given when it was opened, and those of its own slip
        that it could not yet write into the book, each with the
        acknowledgement the writer signed for it; and a cancellation whose
        acknowledgement still waits to follow it into the book, with that
        acknowledgement. They live only in this writer. Keep them with the
        book, and hand them in again (options "cancellations") when a writer
        is opened again from the book: a writer opened without them knows
        nothing of them. Copies, each as it is handed to a check:
        {"cancellation", "stamps"?, "acknowledgements"?}. To keep them together
        with the book, read both with snapshot()."""
        return self._quietly(lambda: copy.deepcopy(self._beside()))

    def add(self, entry):
        """Add an entry that someone else made (a seal, a cancellation, a
        refusal) to the book. It is added only if the book still passes its
        check with it, and it is not dated ahead of the clock.

        A cancellation is a special case: whatever is wrong with what stands
        beside it, a cancellation that the person signed is not lost.
          - If the entry cannot be added as it was handed over (a faulty
            time-stamp beside it, a member that cannot be written as a
            line), the cancellation is added with the time-stamps that pass
            their check, or by itself, without what else stood beside it,
            if the book passes its check with that.
          - If it cannot be added even so (a date ahead of the clock), but
            is signed with the passkey the slip names, the writer keeps it
            as the person's own copy and allows nothing more under the
            slip. It writes it into the book, at its next call, once the
            clock has reached its date.
        In both cases the call still fails, and the error says what was done.

        Whenever the person's cancellation of this writer's own slip is
        handed to "add", the writer signs an acknowledgement: its agent's
        statement that it was handed the cancellation, and when. It is
        handed back, to be given to the person, and it follows the
        cancellation into the book. One cancellation is acknowledged once:
        the same acknowledgement is handed back each time, also by a writer
        opened again and given what "cancellations" handed back.

        Returns {} or, for the person's cancellation of this writer's slip,
        {"acknowledgement": the record, or None where none could be signed}.
        Raises a Refusal, "record-not-sound", if the entry cannot be added as
        it was handed over. Nothing is added, except a cancellation by
        itself as set out above. Where the person's cancellation of this
        writer's slip was handed over, the error's "acknowledgement" holds
        the acknowledgement."""
        # What is handed over is read once, member by member, when it is
        # handed over: the members a line of a book lists, and the three of
        # a cancellation by their names. Each is copied as it is read. A
        # member that cannot be copied makes the entry one that cannot be
        # written as a line. The three members of a cancellation are read
        # first, each with room for a line of its own, so that nothing
        # handed over beside them can keep them from being read. The other
        # members share one line's room: once one of them cannot be copied,
        # the entry cannot be a line, and the rest are not read. Anything
        # but an object (a list, text, None) cannot be a line, and is not
        # written out.
        read = {}
        listed = None
        if isinstance(entry, Mapping):
            try:
                # A name that is a number (or True, False, None) is the text JavaScript
                # would give it; any other name makes the entry not plain data, but the
                # three members of a cancellation are still read.
                named = {}
                strange = False
                for name, item in entry.items():
                    try:
                        named[_js.property_key(name)] = item
                    except TypeError:
                        strange = True
                entry = named
                listed = _js.keys(entry)
                known = [name for name in ('cancellation', 'stamps', 'acknowledgements') if name in entry]
                rest = _copier()
                whole = True
                members = known + [name for name in listed if name not in known]
                if strange:
                    # A name that is not plain data: the entry cannot be a line, though
                    # its other members are read.
                    listed = listed + [_STRANGE]
                for name in members:
                    own = name in known
                    if not own and not whole:
                        read[name] = None
                        continue
                    try:
                        read[name] = {'value': _copy_of(entry[name]) if own else rest(entry[name])}
                    except Exception:
                        read[name] = None
                        if not own:
                            whole = False
            except Exception:
                listed = []
                read.clear()

        def member(name):
            return read.get(name)

        # The entry is written out once, as text. The text is what is checked, and what is added.
        line = None
        try:
            if listed and all(member(name) is not None for name in listed):
                line = entry_line({name: member(name)['value'] for name in listed})
        except Exception:
            line = None  # it cannot be a line of a book
        # A cancellation is also written out by itself, without what stands beside it.
        alone = None
        try:
            if member('cancellation') is not None:
                alone = entry_line({'cancellation': member('cancellation')['value']})
        except Exception:
            alone = None  # not a record at all
        # And with its time-stamps alone, where more than those stands beside
        # it; and the time-stamps themselves, each as a line would hold it:
        # every one that can be written, from the first sixteen places of the
        # list, so that a faulty item beside a sound time-stamp does not lose it.
        stamped = None
        offered = []
        stamps = member('stamps') if alone is not None else None
        if stamps is not None:
            try:
                if len(listed) > 2:
                    stamped = entry_line({'cancellation': member('cancellation')['value'], 'stamps': stamps['value']})
            except Exception:
                stamped = None
            if isinstance(stamps['value'], list):
                for item in stamps['value'][:_MAX_HANDED]:
                    try:
                        offered.append(_js.parse(canonical_json(item)))
                    except Exception:
                        pass  # not a time-stamp
        # The acknowledgements handed over with it, as "cancellations" hands them back.
        handed = None
        acknowledgements = member('acknowledgements') if alone is not None else None
        try:
            if acknowledgements is not None and isinstance(acknowledgements['value'], list):
                handed = _js.parse(_js.stringify(acknowledgements['value']))
        except Exception:
            handed = None
        return self._in_turn(lambda: self._add(line, alone, stamped, offered, handed, listed))

    def _add(self, line, alone, stamped, offered, handed, listed):
        slip = self._slip
        # The person's cancellation of this writer's own slip stops the
        # writer before anything else is done, the reading of the clock
        # included: whatever fails after this, no action is taken. The
        # acknowledgements handed over with it are sorted at once too, so
        # that a clock that fails loses none of them.
        early = None
        if alone is not None:
            candidate = _js.parse(alone)
            found = answer_of(self._carried, {**self._base, 'cancellations': [candidate]})['result']['held']
            one = found[0] if found else None
            if one and one['used'] and one['slip'] == slip:
                self._stopped = True
                early = {'candidate': candidate, 'one': one, 'others': self._sort_handed(one['fingerprint'], candidate['cancellation'], handed)}

        # Where the writer holds a copy of this cancellation beside its book,
        # the copy takes the acknowledgements handed over now and, where the
        # book does not hold the cancellation, its sound time-stamps: before
        # anything is written into the book. A line of a book is not changed.
        # "keep": where the writer holds no copy, and the book does not hold
        # the cancellation, the writer keeps one, with the sound time-stamps.
        # True where the writer holds a copy afterwards.
        def take_handed(keep, in_book=None):
            if in_book is None:
                in_book = early is not None and early['one']['inBook'] is not None
            if not early:
                return False
            candidate, one, others = early['candidate'], early['one'], early['others']
            holds = next((k for k in self._kept if k['fingerprint'] == one['fingerprint']), None)
            at_opening = (
                None
                if holds
                else next(
                    (h for h in self._given if _js.truthy(h) and _js.truthy(_member(h, 'cancellation')) and _member(h['cancellation'], 'payload') == _member(candidate['cancellation'], 'payload')),
                    None,
                )
            )
            held = holds['entry'] if holds else at_opening
            if not held and (in_book or not keep or self._room() <= 0):
                return False
            stamps = (
                None
                if in_book
                else self._merged_stamps(candidate['cancellation'], held['stamps'] if held and 'stamps' in held and isinstance(held['stamps'], list) else [], offered)
            )
            if holds:
                if stamps:
                    holds['entry'] = {**holds['entry'], 'stamps': stamps}
                    holds['tried'] = False
                self._put_handed(holds['entry'], one['fingerprint'], others)
            elif at_opening:
                if stamps:
                    at_opening['stamps'] = stamps
                    item = next((u for u in self._unwritten if u['entry'] is at_opening), None)
                    if item:
                        item['tried'] = False
                self._put_handed(at_opening, one['fingerprint'], others)
            else:
                copied = {'cancellation': candidate['cancellation']}
                if stamps:
                    copied['stamps'] = stamps
                self._put_handed(copied, one['fingerprint'], others)
                self._kept.append({'entry': copied, 'when': nan_time(one['content']['when']), 'fingerprint': one['fingerprint'], 'tried': False})
            return True

        # The clock is read once for the whole call.
        try:
            at = self._now()
        except Exception as e:
            # The cancellation is kept, with its sound time-stamps and the
            # acknowledgements handed over with it, so that none is lost with
            # the call.
            holding = take_handed(True)
            # An acknowledgement of the agent's own, taken for a cancellation
            # the book holds, waits to follow it into the book, and is handed
            # back meanwhile, as one that could not be written at once does.
            fp = early['one']['fingerprint'] if early else None
            if early and early['one']['inBook'] is not None and fp in self._acknowledged and fp not in self._written:
                self._waiting[fp] = early['candidate']['cancellation']
            if early and early['one']['inBook'] is None and not holding:
                full = self._refused(
                    'The clock failed, so nothing was written into the book. The cancellation is signed with the passkey the slip names, so the stub writer '
                    'allows nothing more under that slip. It already holds as many cancellations beside its book as it can, so this one is not kept: hand it over again later.',
                )
                full.cause = e
                raise full from e
            raise
        take_handed(False)
        self._write_waiting(at)
        why = 'it cannot be written as a line of a book.'
        if line is not None:
            whole = self._take_line(line, at)
            if whole['fits']:
                # An added stub of this writer's own chain moves its place in the chain on.
                self._after = self._last_stub(whole['checked']['entries'])
                last = whole['checked']['entries'][-1]
                if last['kind'] == 'cancellation' and last.get('slip') == slip and last['verified'] == 'all':
                    self._stopped = True
                    return {'acknowledgement': self._acknowledge(last['fingerprint'], _js.parse(line)['cancellation'], True, at)}
                return {}
            why = whole['why']
        if alone is None:
            raise _not_written(f'The entry was not added: {why}')
        # The cancellation with its time-stamps, then with those of them that
        # pass their check, then by itself, where it was handed over with more.
        cancellation_record = _js.parse(alone)['cancellation']
        sound = self._merged_stamps(cancellation_record, [], offered)
        with_sound = entry_line({'cancellation': cancellation_record, 'stamps': sound}) if sound else None
        added = None
        tried = {line}
        for form in (stamped, with_sound, alone):
            if form is None or form in tried or added is not None:
                continue
            tried.add(form)
            if self._take_line(form, at)['fits']:
                added = form
        # Whether the person signed it, for this writer's own slip, and
        # whether the book now holds it: checked without any other cancellation.
        candidate = _js.parse(added if added is not None else alone)
        found = answer_of(self._carried, {**self._base, 'cancellations': [candidate]})['result']['held']
        one = found[0] if found else None
        own = bool(one and one['used'] and one['slip'] == slip)
        stops = ' It is signed with the passkey the slip names, so the stub writer allows nothing more under that slip.' if own else ''
        if own:
            self._stopped = True
        if added is not None:
            acknowledgement = self._acknowledge(one['fingerprint'], candidate['cancellation'], True, at) if own else None
            if added == stamped:
                how = 'The cancellation was added to the book with its time-stamps, without what else stood beside it.'
            elif added == with_sound:
                how = 'The cancellation was added to the book with those of its time-stamps that pass their check, without what else stood beside it.'
            else:
                how = 'The cancellation by itself was added to the book, without what stood beside it.'
            raise self._refused(f'The cancellation was not added as it was handed over: {why} {how}{stops}', acknowledgement)
        if own:
            in_book = one['inBook'] is not None
            acknowledgement = self._acknowledge(one['fingerprint'], candidate['cancellation'], in_book, at)
            holding = take_handed(True, in_book)
            if in_book:
                how = (
                    ' It was written into the book in this call, from the copy the stub writer held beside it, with the time-stamps that copy holds.'
                    if early and early['one']['inBook'] is None
                    else ''
                )
                raise self._refused(f'The book already holds this cancellation, so it was not added again.{how}{stops}', acknowledgement)
            if not holding:
                raise self._refused(
                    f'The cancellation was not added: {why}{stops} The stub writer already holds as many cancellations beside its book as it can, so this one is not kept: hand it over again later.',
                    acknowledgement,
                )
            raise self._refused(f'The cancellation was not added: {why}{stops}', acknowledgement)
        raise _not_written(f'The entry was not added: {why}')
