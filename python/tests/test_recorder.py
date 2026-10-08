# The stub writer and the connector for an agent's tools: what only the
# Python version has to show. The shared scenarios (test_vectors.py, with
# test-vectors/recorder-scenarios.json and tool-scenarios.json) show that
# both give the same answers as the JavaScript library, step by step. Here:
# calls from several threads, a call from inside an action or from the other
# side while it countersigns, functions that give a coroutine, values that
# only Python has (a datetime, a tuple, a dict subclass), and keys kept
# between runs as their seeds.

import asyncio
import contextvars
import datetime
import threading
import time
import unittest
from collections import OrderedDict

from test_records import ORIGIN, RP_ID, Passkey

from provared import (
    NotTaken,
    Recorder,
    Refusal,
    arguments_fingerprint,
    check_book,
    countersign,
    fingerprint,
    from_base64url,
    generate_key_set,
    key_set_from_seeds,
    key_set_seeds,
    open_recorder,
    record_tools,
    thumbprint,
    write_book,
)
from provared.approval import assemble_approval, prepare_approval
from provared.encoding import parse_time
from provared.jws import parse_record, signing_input
from provared.recorder import _time_value
from provared.signatures import verify_signature
from provared.slip import assemble_slip, prepare_slip
from provared.standing import assemble_cancellation, prepare_cancellation

START = parse_time('2026-10-05T09:00:00Z')
HOUR = 3600 * 1000
MINUTE = 60 * 1000
ORDER = 'supplies.order'
INSIDE = 'The stub writer was called from inside an action it is taking. Call it once the action has ended.'


def order(value):
    return {'action': ORDER, 'amount': {'unit': 'GBP', 'value': value}, 'with': 'supplier'}


class World:
    """A person with a stand-in passkey, an agent, a service and a signed slip."""

    def __init__(self, **fields):
        self.passkey = Passkey()
        self.agent_keys, self.agent = generate_key_set()
        self.service_keys, self.service = generate_key_set()
        prepared = prepare_slip({
            'issuer': {'name': 'Sam Example', 'key': self.passkey.key, 'rpId': RP_ID, 'origin': ORIGIN},
            'agent': {'name': 'Office supplies agent', 'keys': self.agent_keys},
            'actions': [ORDER, 'provared.data.read'],
            'limits': [{'action': ORDER, 'max': 200, 'unit': 'GBP'}],
            'with': [{'id': 'supplier', 'name': 'Example Stationery (invented)', 'keys': self.service_keys}],
            'validFrom': '2026-10-05T08:00:00Z',
            'validUntil': '2026-10-12T08:00:00Z',
            'purpose': 'Keep the office stocked with paper, pens and toner.',
            **fields,
        })
        self.slip = assemble_slip(prepared, *self.passkey.sign(prepared['challenge']))
        self.slip_fingerprint = fingerprint(from_base64url(self.slip['payload']))
        self.issuer_keys = [thumbprint(self.passkey.key)]
        self.clock = START + HOUR

    def book(self):
        return write_book([{'slip': self.slip}])

    def open(self, **more):
        options = {'book': self.book(), 'slip': self.slip_fingerprint, 'private_keys': self.agent, 'issuer_keys': self.issuer_keys, 'now': lambda: self.clock, **more}
        return open_recorder(**options)

    def cancel(self, when):
        prepared = prepare_cancellation({'slip': self.slip_fingerprint, 'when': when})
        return {'cancellation': assemble_cancellation(prepared, *self.passkey.sign(prepared['challenge']))}

    def approve(self, request, when):
        prepared = prepare_approval({'slip': self.slip_fingerprint, **request, 'when': when})
        return {'record': assemble_approval(prepared, *self.passkey.sign(prepared['challenge']))}


class Seeds(unittest.TestCase):
    def test_a_key_set_is_kept_as_its_seeds_and_loaded_again(self):
        keys, private_keys = generate_key_set()
        ed, ml = key_set_seeds(private_keys)
        self.assertEqual((len(ed), len(ml)), (32, 32))
        again_keys, again_private = key_set_from_seeds(ed, ml)
        self.assertEqual(again_keys, keys)
        self.assertEqual(key_set_seeds(again_private), (ed, ml))
        # What the loaded keys sign checks against the public keys made first.
        from provared.stub import sign_with_key_set

        record, _ = sign_with_key_set('acknowledgement', {'type': 'provared.acknowledgement.v0', 'id': 'A' * 22, 'slip': 'A' * 43, 'cancellation': 'A' * 43, 'when': '2026-10-05T09:00:00Z'}, again_private)
        parsed = parse_record(record, 'acknowledgement')
        for key, s in zip(keys, parsed.signatures):
            self.assertEqual(verify_signature(key, s['signature'], signing_input(s['protected_b64'], parsed.payload_b64)), 'valid')

    def test_the_seeds_are_those_of_rfc_8032_and_fips_204(self):
        # Seeds of 32 bytes in, the same public keys out, whatever made them.
        ed, ml = bytes(range(32)), bytes(range(32, 64))
        self.assertEqual(key_set_from_seeds(ed, ml)[0], key_set_from_seeds(bytearray(ed), memoryview(ml))[0])
        for wrong in (bytes(31), bytes(33), b''):
            with self.assertRaises(ValueError):
                key_set_from_seeds(wrong, ml)
            with self.assertRaises(ValueError):
                key_set_from_seeds(ed, wrong)


class Threads(unittest.TestCase):
    def test_calls_from_several_threads_are_taken_one_after_the_other(self):
        w = World()
        writer = w.open()
        results = []
        barrier = threading.Barrier(4)

        def act(value):
            barrier.wait()

            def perform():
                time.sleep(0.05)
                return value

            results.append(writer.act(order(value), perform))

        threads = [threading.Thread(target=act, args=(150,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Each saw the book as the one before left it: only one order of 150 fits a limit of 200.
        self.assertEqual(sorted(r['done'] for r in results), [False, False, False, True])
        r = check_book(writer.book(), {'issuerKeys': w.issuer_keys})
        self.assertEqual(r['summary']['counts']['stubs'], 1)
        self.assertTrue(r['summary']['withinSlips'])

    def test_a_call_from_inside_an_action_is_refused_at_once(self):
        w = World()
        writer = w.open()
        seen = {}

        def perform():
            seen['book'] = writer.book()
            seen['held'] = writer.cancellations()
            for name, call in (('check', writer.check), ('before', lambda: writer.before(order(1))), ('act', lambda: writer.act(order(1), lambda: None)), ('add', lambda: writer.add({'neither': 'this'}))):
                try:
                    call()
                    seen[name] = 'taken'
                except RuntimeError as e:
                    seen[name] = str(e)
            # From a thread started with the action's own context: refused too, not waiting for ever.
            context = contextvars.copy_context()
            out = []
            t = threading.Thread(target=context.run, args=(lambda: out.append(_attempt(writer.check)),))
            t.start()
            t.join(5)
            seen['thread'] = out
            return 'done'

        r = writer.act(order(10), perform)
        self.assertTrue(r['done'])
        self.assertEqual(seen['book'], w.book())
        self.assertEqual(seen['held'], [])
        for name in ('check', 'before', 'act', 'add'):
            self.assertEqual(seen[name], INSIDE, name)
        self.assertEqual(seen['thread'], [INSIDE])
        # Once the action has ended, the writer is called as before.
        self.assertEqual(writer.check()['summary']['counts']['stubs'], 1)

    def test_a_call_from_the_other_side_while_it_countersigns_is_refused_and_the_time_runs_out(self):
        w = World()
        writer = w.open(countersign_within=200)
        tried = []

        def countersigner(stub):
            tried.append(_attempt(writer.check))
            return countersign(stub, w.service, w.clock + 1000)

        r = writer.act(order(10), lambda: 'done', {'countersign': countersigner})
        self.assertEqual(tried, [INSIDE])
        self.assertTrue(r['stub']['countersignature']['accepted'])
        # One that does not answer in time: the stub is written one-sided, and what it gives later is not used.
        late = threading.Event()

        def slow(stub):
            time.sleep(0.6)
            late.set()
            return countersign(stub, w.service, w.clock + 1000)

        started = time.monotonic()
        r = writer.act(order(10), lambda: 'done', {'countersign': slow})
        self.assertLess(time.monotonic() - started, 0.55)
        self.assertEqual(r['stub']['countersignature'], {'accepted': False, 'problem': {'code': 'countersignature-missing', 'message': 'Asking the other side for its countersignature failed, or took too long.'}})
        self.assertTrue(late.wait(5))
        self.assertEqual(check_book(writer.book())['summary']['counts']['oneSided'], 1)

    def test_a_clock_that_calls_the_writer_is_refused_rather_than_waiting_for_ever(self):
        w = World()
        holder = {}

        def clock():
            if 'writer' in holder:
                holder['tried'] = _attempt(holder['writer'].check)
            return w.clock

        writer = w.open(now=clock)
        holder['writer'] = writer
        self.assertTrue(writer.act(order(1), lambda: None)['done'])
        self.assertEqual(holder['tried'], INSIDE)


class Coroutines(unittest.TestCase):
    def test_an_action_that_gives_a_coroutine_is_refused_and_leaves_no_stub(self):
        w = World()
        writer = w.open()

        async def perform():
            return 'never run'

        with self.assertRaises(TypeError):
            writer.act(order(10), perform)
        self.assertEqual(writer.book(), w.book())

    def test_a_countersignature_that_comes_as_a_coroutine_is_not_used(self):
        w = World()
        writer = w.open()

        async def countersigner(stub):
            return countersign(stub, w.service, w.clock + 1000)

        r = writer.act(order(10), lambda: 'done', {'countersign': countersigner})
        self.assertTrue(r['done'])
        self.assertFalse(r['stub']['countersignature']['accepted'])
        self.assertEqual(r['stub']['countersignature']['problem']['code'], 'countersignature-missing')

    def test_a_tool_whose_functions_give_coroutines_is_refused(self):
        w = World()
        writer = w.open()

        async def run(args):
            return 'never run'

        async def details(args):
            return []

        tools = record_tools(writer, {'look': {'action': 'provared.data.read', 'run': run}, 'documents': {'action': 'provared.data.read', 'details': details, 'run': lambda args: 1}})
        with self.assertRaises(TypeError):
            tools['look']({'q': 1})
        with self.assertRaises(TypeError):
            tools['documents']({'q': 1})
        self.assertEqual(writer.book(), w.book())
        # A coroutine is not plain data: an amount that comes as one is refused as such.
        tools = record_tools(writer, {'order': {'action': ORDER, 'with': 'supplier', 'amount': lambda args: asyncio.sleep(0), 'run': lambda args: 1}})
        with self.assertRaises(Refusal) as refused:
            tools['order']({'q': 1})
        self.assertEqual(refused.exception.code, 'bad-field')


class PythonValues(unittest.TestCase):
    def test_a_date_may_be_handed_over_as_a_datetime(self):
        moment = datetime.datetime(2026, 10, 5, 10, 0, 0, 500000, tzinfo=datetime.timezone.utc)
        self.assertEqual(_time_value(moment), START + HOUR + 500)
        self.assertEqual(_time_value(moment.astimezone(datetime.timezone(datetime.timedelta(hours=2)))), START + HOUR + 500)
        # One with no time zone, a date, text and True would be read by rules that
        # differ from one device to another: they are refused, as in JavaScript.
        for value in (datetime.date(2026, 10, 5), datetime.datetime(2026, 10, 5, 10, 0), '2026-10-05T10:00:00Z', True):
            with self.assertRaises(Refusal) as refused:
                _time_value(value)
            self.assertEqual(refused.exception.code, 'bad-field')
        w = World()
        writer = w.open()
        r = writer.act(order(1), lambda: None, {'when': moment})
        self.assertTrue(r['done'])
        self.assertEqual(check_book(writer.book())['entries'][1]['content']['when'], '2026-10-05T10:00:00Z')

    def test_what_is_not_plain_data_is_refused_where_javascript_could_not_copy_it(self):
        w = World()
        writer = w.open()
        for request in ({**order(1), 'details': ({'name': 'x', 'sha256': 'A' * 43},)}, {**order(1), 'note': b'bytes'}, {**order(1), 'call': print}):
            with self.assertRaises(Refusal) as refused:
                writer.before(request)
            self.assertEqual(refused.exception.code, 'bad-field')
        loop = {'action': ORDER}
        loop['self'] = loop
        with self.assertRaises(Refusal):
            writer.record(loop)
        # A dict of another class is copied as a plain one.
        self.assertTrue(writer.act(OrderedDict(order(1)), lambda: None)['done'])

    def test_the_fingerprint_of_the_arguments_takes_only_json(self):
        self.assertEqual(arguments_fingerprint({'n': 2**60}), arguments_fingerprint({'n': float(2**60)}))
        self.assertEqual(arguments_fingerprint({'n': -0.0}), arguments_fingerprint({'n': 0}))
        self.assertEqual(arguments_fingerprint([True, 1]), fingerprint(b'[true,1]'))
        for bad in ((1, 2), OrderedDict(a=1), {1: 'a'}, b'x', 10**400, float('nan'), {'a': {1, 2}}):
            with self.assertRaises(Refusal) as refused:
                arguments_fingerprint(bad)
            self.assertEqual(refused.exception.code, 'bad-field')
        # Through a tool the arguments are copied first, as plain data: a dict of another class is a dict.
        w = World()
        writer = w.open()
        tools = record_tools(writer, {'look': {'action': 'provared.data.read', 'run': lambda args: args}})
        self.assertEqual(tools['look'](OrderedDict(q=1)), {'q': 1})
        self.assertEqual(check_book(writer.book())['entries'][1]['content']['details'][0]['sha256'], arguments_fingerprint({'q': 1}))

    def test_the_options_may_be_named_in_pythons_way(self):
        w = World()
        cancel = w.cancel(w.clock)
        writer = w.open(options={'cancellations': [cancel]})
        snake = w.open(options={'withoutMethods': [], 'cancellations': []} | {'cancellations': [cancel]})
        self.assertEqual(writer.before(order(1)), snake.before(order(1)))
        self.assertFalse(writer.before(order(1))['allowed'])
        named = w.open(options={'without_methods': ['ES256']})
        self.assertEqual(named.before(order(1))['problems'][0]['message'], 'This device could not check every signature in the record so far.')

    def test_a_tool_may_be_described_by_an_object_and_tells_whoever_asked_after_each_stub(self):
        w = World(requires=[{'need': 'approval', 'action': ORDER, 'above': 40, 'unit': 'GBP'}])
        writer = w.open()

        class Order:
            action = ORDER
            amount = {'unit': 'GBP', 'value': 45}

            def __init__(self):
                self.asked = 0

            def run(self, args):
                return f"ordered {args['item']}"

            def approve(self, request, args):
                self.asked += 1
                return None

        description = Order()
        description.__dict__['with'] = 'supplier'
        told = []
        tools = record_tools(writer, {'order': description}, on_stub=lambda stub, tool: told.append((tool, stub['seq'])))
        with self.assertRaises(NotTaken) as refused:
            tools['order']({'item': 'toner'})
        self.assertEqual(refused.exception.tool, 'order')
        self.assertEqual([b['code'] for b in refused.exception.answer['breaches']], ['approval-missing'])
        self.assertTrue(str(refused.exception).startswith('The tool "order" was not run. '))
        self.assertEqual(description.asked, 1)
        self.assertEqual(told, [])
        # With the approval the person signs, it is taken, and whoever asked is told.
        request = {'action': ORDER, 'with': 'supplier', 'amount': {'unit': 'GBP', 'value': 45}, 'details': [{'name': 'arguments', 'sha256': arguments_fingerprint({'item': 'toner'})}]}
        approval = w.approve(request, w.clock)
        description.approve = lambda request, args: approval
        tools = record_tools(writer, {'order': description}, {'onStub': lambda stub, tool: told.append((tool, stub['seq']))})
        self.assertEqual(tools['order']({'item': 'toner'}), 'ordered toner')
        self.assertEqual(told, [('order', 0)])
        self.assertIsInstance(writer, Recorder)


def _attempt(call):
    try:
        call()
        return 'taken'
    except RuntimeError as e:
        return str(e)


if __name__ == '__main__':
    unittest.main()
