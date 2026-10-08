# Scenarios for the stub writer (open_recorder) and the connector for an
# agent's tools (record_tools), played by this library. The JavaScript
# library plays the same scenarios (test/helpers/scenarios.mjs at the top
# of the repository), and the two transcripts must be the same: see that
# file for what a scenario holds and how a transcript is written.

import base64
import contextlib
import hashlib
import math
import os
import re
import threading
import time

from provared import _js, encoding
from provared.book import check_book
from provared.encoding import Refusal
from provared.recorder import _ABSENT, open_recorder
from provared.signatures import key_set_from_seeds
from provared.stub import countersign
from provared.tools import NotTaken, arguments_fingerprint, record_tools

_UNDEF = object()


def _seed(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


# --- the same unique numbers in both runners ---


class _Ids:
    """Stands in for the "os" module in provared.encoding, for random_id: the
    n-th 16 bytes asked for are the first 16 bytes of SHA-256 of
    "provared-scenario-id-n". Any other request is os.urandom's."""

    def __init__(self):
        self.n = 0

    def urandom(self, size):
        if size != 16:
            return os.urandom(size)
        self.n += 1
        return hashlib.sha256(f'provared-scenario-id-{self.n}'.encode()).digest()[:16]


@contextlib.contextmanager
def _fixed_ids():
    original = encoding.os
    encoding.os = _Ids()
    try:
        yield
    finally:
        encoding.os = original


# --- the transcript ---

_TOKEN = re.compile(r'[A-Za-z0-9_-]{20,}')
_SIGNATURE_LENGTH = 6170  # ML-DSA-87: 4,627 bytes in base64url
_INSIDE = 'The stub writer was called from inside an action it is taking. Call it once the action has ended.'
_MESSAGES = {'the clock failed', 'no answer in time', _INSIDE, 'Invalid time value'}


def _strings(value, out):
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out)
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out)
    return out


def _hashed(token):
    return 'h:' + hashlib.sha256(token.encode()).hexdigest()[:16]


class _Context:
    def __init__(self, scenario):
        self.world = scenario['world']
        self.keys = {}
        self.writers = {}
        self.tools = {}
        self.acks = {}
        self.clock = _Clock(self.world['start'])
        self.known = set()
        for s in _strings([scenario['world'], scenario['steps']], []):
            for t in _TOKEN.findall(s):
                if len(t) == _SIGNATURE_LENGTH:
                    self.known.add(t)
        self.thrown = set()
        self._gather(scenario['steps'])
        self._names = {}
        self._counts = {}

    def _gather(self, value):
        if isinstance(value, list):
            for v in value:
                self._gather(v)
        elif isinstance(value, dict):
            for k, v in value.items():
                if k == 'throws' and isinstance(v, str):
                    self.thrown.add(v)
                else:
                    self._gather(v)

    def name(self, value, kind):
        if value not in self._names:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._names[value] = f'{kind}{self._counts[kind]}'
        return self._names[value]


def _token(t, ctx):
    if len(t) == _SIGNATURE_LENGTH and t not in ctx.known:
        return ctx.name(t, 'sig')
    return _hashed(t) if len(t) > 64 else t


def norm(value, ctx, key=None):
    """A value as the transcript holds it: as JSON would carry it, with long and random values named."""
    if value is None or value is _UNDEF:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return ctx.name(value, 'root') if key == 'root' else _TOKEN.sub(lambda m: _token(m.group(0), ctx), value)
    if isinstance(value, (int, float)):
        return value if math.isfinite(value) else None
    if isinstance(value, (list, tuple)):
        return [norm(v, ctx) for v in value]
    if isinstance(value, dict):
        out = {}
        for k in _js.sort_strings(value.keys()):
            if value[k] is _UNDEF or callable(value[k]):
                continue
            out[k] = norm(value[k], ctx, k)
        return out
    return None


def _message(e, ctx):
    text = e.message if isinstance(getattr(e, 'message', None), str) else str(e)
    return text if text in _MESSAGES or text in ctx.thrown else 'unexpected'


def _failure(e, ctx):
    """An error as the transcript holds it."""
    if isinstance(e, NotTaken):
        return {'error': {'kind': 'NotTaken', 'tool': e.tool, 'message': e.message, 'answer': norm(e.answer, ctx)}}
    if isinstance(e, Refusal):
        out = {'kind': 'Refusal', 'code': e.code, 'message': norm(e.message, ctx)}
        if _js.truthy(getattr(e, 'acknowledgement', None)):
            out['acknowledgement'] = norm(e.acknowledgement, ctx)
        if getattr(e, 'cause', None) is not None:
            out['cause'] = _message(e.cause, ctx)
        return {'error': out}
    return {'error': {'kind': 'Error', 'message': _message(e, ctx)}}


# --- the values in a step ---

_SPECIAL = {'NaN': float('nan'), 'Infinity': float('inf'), '-Infinity': float('-inf'), '-0': -0.0, 'undefined': _UNDEF}


def resolve(value, ctx):
    """A value of a step, with its expressions worked out. JavaScript's
    undefined is left out of an object, and is None anywhere else."""
    if isinstance(value, list):
        return [None if v is _UNDEF else v for v in (resolve(x, ctx) for x in value)]
    if not isinstance(value, dict):
        return value
    if '$ref' in value:
        if value['$ref'] not in ctx.world['records']:
            return None
        return resolve(_js.parse(_js.stringify(ctx.world['records'][value['$ref']])), ctx)
    if '$ack' in value:
        found = ctx.acks.get(value['$ack'])
        return None if found is None else _js.parse(_js.stringify(found))
    if '$book' in value:
        return ctx.writers[value['$book']].book()
    if '$held' in value:
        held = ctx.writers[value['$held']].cancellations()
        return held[value['index']] if 'index' in value else held
    if '$lines' in value:
        return '\n'.join(resolve(value['$lines'], ctx).split('\n')[value['from']:value['to']]) + '\n'
    if '$with' in value:
        out = dict(resolve(value['$with'], ctx))
        out.update(resolve(value['set'], ctx))
        return {k: v for k, v in out.items() if v is not _UNDEF}
    if '$concat' in value:
        return ''.join(resolve(v, ctx) for v in value['$concat'])
    if '$repeat' in value:
        return value['$repeat'] * value['n']
    if '$fill' in value:
        return [resolve(value['$fill'], ctx)] * value['n']
    if '$nest' in value:
        v = resolve(value['leaf'], ctx)
        for _ in range(value['$nest']):
            v = [v]
        return v
    if '$shared' in value:
        v = resolve(value['leaf'], ctx)
        for _ in range(value['$shared']):
            v = {f'm{b}': v for b in range(value['width'])}
        return v
    if '$' in value:
        return _SPECIAL[value['$']]
    out = {}
    for k, v in value.items():
        r = resolve(v, ctx)
        if r is not _UNDEF:
            out[k] = r
    return out


def _top(value):
    return None if value is _UNDEF else value


# --- the clock ---


class _Clock:
    def __init__(self, start):
        self.time = start
        self.fail = False
        self.left = 0
        self.readings = 0
        self.gives = None
        self.giving = False

    def now(self):
        self.readings += 1
        if self.fail:
            raise Exception('the clock failed')
        if self.left > 0:
            self.left -= 1
            if self.left == 0:
                raise Exception('the clock failed')
        return self.gives if self.giving else self.time


# --- what the caller hands to the writer ---


def _order(value):
    return {'action': 'supplies.order', 'amount': {'unit': 'GBP', 'value': value}, 'with': 'supplier'}


def _inside(names, ctx, writer):
    """A call to the writer from inside something it runs: what came of it."""
    out = []
    for name in names:
        try:
            if name == 'book':
                value = writer.book()
            elif name == 'held':
                value = writer.cancellations()
            elif name == 'check':
                value = writer.check()['summary']
            elif name == 'before':
                value = writer.before(_order(1))
            elif name == 'act':
                value = writer.act(_order(1), lambda: None)['done']
            elif name == 'record':
                value = writer.record(_order(1))['seq']
            elif name == 'add':
                value = writer.add({'neither': 'this nor that'})
            got = {'value': norm(value, ctx)}
        except Exception as e:
            got = _failure(e, ctx)
        out.append(got)
    return out


def _countersigner(spec, ctx, writer, seen):
    """The other side, asked to countersign. "seen" gathers what it was handed and did."""
    if 'notFunction' in spec:
        return _top(resolve(spec['notFunction'], ctx))

    def other(stub):
        seen['asked'] = seen.get('asked', 0) + 1
        seen.setdefault('handed', []).append(norm(stub['payload'], ctx))
        if spec.get('never'):
            threading.Event().wait(5)
            return None
        if spec.get('late'):
            when = ctx.clock.time + spec.get('at', 1000)
            time.sleep(spec['late'] / 1000)
            return countersign(stub, ctx.keys[spec['sign']][1], when)
        if spec.get('inside'):
            seen.setdefault('inside', []).append(_inside(spec['inside'], ctx, writer))
        if 'throws' in spec:
            raise Exception(spec['throws'])
        if 'gives' in spec:
            return _top(resolve(spec['gives'], ctx))
        return countersign(stub, ctx.keys[spec['sign']][1], ctx.clock.time + spec.get('at', 1000))

    return other


def _more_of(spec, ctx, writer, seen):
    if spec is None:
        return None
    # Anything but an object is handed to the writer as it is.
    if not isinstance(spec, dict):
        return _top(resolve(spec, ctx))
    more = {}
    for name in ('when', 'terms', 'approval'):
        if name in spec:
            value = resolve(spec[name], ctx)
            if value is not _UNDEF:
                more[name] = value
    if spec.get('countersign'):
        seen['countersign'] = {}
        more['countersign'] = _countersigner(spec['countersign'], ctx, writer, seen['countersign'])
    return more


def _performer(spec, ctx, writer, seen):
    if 'notFunction' in spec:
        return _top(resolve(spec['notFunction'], ctx))

    def perform():
        seen['performed'] = seen.get('performed', 0) + 1
        if spec.get('inside'):
            seen['inside'] = _inside(spec['inside'], ctx, writer)
        if 'throws' in spec:
            raise Exception(spec['throws'])
        return _top(resolve(spec.get('gives'), ctx))

    return perform


# --- a tool's description ---


def _tool_of(name, spec, ctx, writer, seens):
    def seen():
        return seens['current'].setdefault(name, {})

    def note(member, value):
        seen().setdefault(member, []).append(norm(value, ctx))

    def meddle(args, member):
        if isinstance(args, dict):
            args['item'] = f'changed by {member}'

    def fn(member, make):
        value = spec[member]
        if isinstance(value, dict) and 'fn' in value:
            return make(value['fn'])
        return _top(resolve(value, ctx))

    tool = {}
    if 'action' in spec:
        tool['action'] = _top(resolve(spec['action'], ctx))
    if 'run' in spec:

        def make_run(f):
            def run(args):
                note('run', args)
                if f.get('meddle'):
                    meddle(args, 'run')
                if 'throws' in f:
                    raise Exception(f['throws'])
                if 'field' in f:
                    found = isinstance(args, dict) and f['field'] in args
                    return f"{f.get('prefix', '')}{_text(args[f['field']]) if found else 'undefined'}"
                return _top(resolve(f.get('gives'), ctx))

            return run

        tool['run'] = fn('run', make_run)
    for member in ('amount', 'with'):
        if member not in spec:
            continue

        def make_value(f, member=member):
            def give(args):
                note(member, args)
                if f.get('meddle'):
                    meddle(args, member)
                if member == 'amount':
                    found = _top(resolve(f['gives'], ctx)) if 'gives' in f else {'unit': f['unit'], 'value': args.get(f['field']) if isinstance(args, dict) else None}
                    seens['kept']['amount'] = found
                    return found
                if 'gives' in f:
                    return _top(resolve(f['gives'], ctx))
                return args.get(f['field']) if isinstance(args, dict) else None

            return give

        tool[member] = fn(member, make_value)
    if 'details' in spec:

        def make_details(f):
            def details(args):
                note('details', args)
                if f.get('meddle'):
                    meddle(args, 'details')
                seens['kept']['details'] = _top(resolve(f.get('gives'), ctx))
                return seens['kept']['details']

            return details

        tool['details'] = fn('details', make_details)
    if 'countersign' in spec:

        def make_countersign(f):
            other = _countersigner(f, ctx, writer, {})

            def counter(stub, args):
                note('countersign', args)
                if f.get('meddle'):
                    meddle(args, 'countersign')
                return other(stub)

            return counter

        tool['countersign'] = fn('countersign', make_countersign)
    if 'approve' in spec:

        def make_approve(f):
            def approve(request, args):
                note('approve', [request, args])
                if f.get('meddle'):
                    meddle(args, 'approve')
                    if isinstance(request, dict) and request.get('amount'):
                        request['amount']['value'] = 1
                if f.get('mutateKept'):
                    if seens['kept'].get('amount'):
                        seens['kept']['amount']['value'] = 46
                    if seens['kept'].get('details'):
                        seens['kept']['details'][0]['sha256'] = 'E' * 43
                return _top(resolve(f.get('gives'), ctx))

            return approve

        tool['approve'] = fn('approve', make_approve)
    return tool


def _text(value):
    """`${value}` in JavaScript, for the values a scenario uses."""
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return _js.number_string(value)
    return str(value)


# --- one step ---


def _play_step(step, ctx):
    w = ctx.writers.get(step['w']) if 'w' in step else None
    seen = {}
    op = step['op']
    try:
        if op == 'open':
            options = {}
            if 'pass' in step:
                options['pass_'] = _top(resolve(step['pass'], ctx))
            if 'options' in step:
                options['options'] = _top(resolve(step['options'], ctx))
            if 'countersignWithin' in step:
                options['countersign_within'] = _top(resolve(step['countersignWithin'], ctx))
            ctx.writers[step['as']] = open_recorder(
                _top(resolve(step['book'], ctx)),
                _top(resolve(step['slip'], ctx)),
                ctx.keys[step['keys']][1],
                _top(resolve(step['issuerKeys'], ctx)),
                now=ctx.clock.now,
                **options,
            )
            return {'ok': True}
        if op == 'clock':
            c = ctx.clock
            if 'set' in step:
                c.time = step['set']
            if 'add' in step:
                c.time += step['add']
            if 'fail' in step:
                c.fail = step['fail']
            if 'failAt' in step:
                c.left = step['failAt']
            if 'gives' in step:
                c.giving = True
                c.gives = _top(resolve(step['gives'], ctx))
            if step.get('real'):
                c.giving = False
            return None
        if op == 'act':
            r = w.act(_top(resolve(step['request'], ctx)), _performer(step.get('perform', {}), ctx, w, seen), _more_of(step.get('more'), ctx, w, seen))
            return {'done': r['done'], 'answer': norm(r['answer'], ctx), 'result': norm(r.get('result'), ctx), 'stub': norm(r.get('stub'), ctx), 'seen': norm(seen, ctx)}
        if op == 'record':
            r = w.record(_top(resolve(step['request'], ctx)), _more_of(step.get('more'), ctx, w, seen))
            return {'stub': norm(r, ctx), 'seen': norm(seen, ctx)}
        if op == 'before':
            return {'answer': norm(w.before(_top(resolve(step['request'], ctx)), _more_of(step.get('more'), ctx, w, seen)), ctx)}
        if op == 'add':
            try:
                r = w.add(_top(resolve(step['entry'], ctx)))
            except Exception as e:
                if 'label' in step:
                    ctx.acks[step['label']] = getattr(e, 'acknowledgement', None)
                raise
            if 'label' in step:
                ctx.acks[step['label']] = r.get('acknowledgement')
            return {'keys': sorted(r.keys()), 'acknowledgement': norm(r.get('acknowledgement'), ctx)}
        if op == 'book':
            return {'book': norm(w.book(), ctx)}
        if op == 'check':
            return {'check': norm(w.check(), ctx)}
        if op == 'held':
            return {'held': norm(w.cancellations(), ctx)}
        if op == 'checkBook':
            return {'check': norm(check_book(_top(resolve(step['text'], ctx)), _top(resolve(step['options'], ctx))), ctx)}
        if op == 'tools':
            seens = {'current': {}, 'kept': {}}
            # "$whole" hands over a value in place of the tools; "recorder" hands over another value in place of the writer.
            if '$whole' in step['tools']:
                tools = _top(resolve(step['tools']['$whole'], ctx))
            else:
                tools = {}
                for name, spec in step['tools'].items():
                    tools[name] = _tool_of(name, spec, ctx, w, seens) if isinstance(spec, dict) else _top(resolve(spec, ctx))
            options = {}
            if 'onStub' in step and step['onStub'] is not None:
                on = step['onStub']

                def on_stub(stub, tool):
                    seens['current'].setdefault('onStub', []).append([tool, stub['seq']])
                    if 'throws' in on:
                        raise Exception(on['throws'])

                options['onStub'] = on_stub
            recorder = _top(resolve(step['recorder'], ctx)) if 'recorder' in step else w
            ctx.tools[step['as']] = {'made': record_tools(recorder, tools, options), 'seens': seens}
            return {'names': list(ctx.tools[step['as']]['made'])}
        if op == 'call':
            t = ctx.tools[step['t']]
            t['seens']['current'] = {}
            t['seens']['kept'] = {}
            run = t['made'][step['tool']]
            try:
                args = resolve(step['args'], ctx) if 'args' in step else _UNDEF
                r = run() if args is _UNDEF else run(args)
                return {'result': norm(r, ctx), 'seen': norm(t['seens']['current'], ctx)}
            except Exception as e:
                return {**_failure(e, ctx), 'seen': norm(t['seens']['current'], ctx)}
        if op == 'fingerprint':
            # JavaScript's undefined, which is not JSON, is the writer's own stand-in for it.
            args = resolve(step['args'], ctx)
            return {'fingerprint': arguments_fingerprint(_ABSENT if args is _UNDEF else args)}
        raise Exception(f'no such step: {op}')
    except Exception as e:
        out = _failure(e, ctx)
        if seen:
            out['seen'] = norm(seen, ctx)
        return out


def play_scenario(scenario):
    """Play a scenario. Returns its transcript: for each step, what it gave
    and how many times the clock was read."""
    ctx = _Context(scenario)
    for name, s in scenario['world']['keys'].items():
        ctx.keys[name] = key_set_from_seeds(_seed(s['ed']), _seed(s['ml']))
    transcript = []
    with _fixed_ids():
        for step in scenario['steps']:
            ctx.clock.readings = 0
            out = _play_step(step, ctx)
            transcript.append({'op': step['op'], 'reads': ctx.clock.readings, 'out': out})
    return transcript
