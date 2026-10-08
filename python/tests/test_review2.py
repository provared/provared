# Faults found by the second independent review of the Python version
# (8 October 2026). Each is now a test.

import asyncio
import threading
import types
import unittest

from test_recorder import HOUR, World, order

from provared import check_book, open_recorder
from provared.signatures import generate_key_set, verify_signature
from provared.encoding import format_time

# The neutral point: a point of small order. With S = 0 it makes a
# signature that, under some libraries, checks for any message.
NEUTRAL = bytes([1]) + bytes(31)


class WeakSignatures(unittest.TestCase):
    def test_a_signature_whose_r_is_of_small_order_is_refused_under_an_honest_key(self):
        keys, _ = generate_key_set()
        self.assertEqual(verify_signature(keys[0], NEUTRAL + bytes(32), b'anything'), 'invalid')

    def test_a_signature_of_the_wrong_length_is_refused(self):
        keys, _ = generate_key_set()
        self.assertEqual(verify_signature(keys[0], bytes(63), b'anything'), 'invalid')


class WhatAddIsHanded(unittest.TestCase):
    def test_a_cancellation_beside_a_member_whose_name_is_not_text_still_stops_the_writer(self):
        for beside in ({1: 'note'}, {None: 'note'}, {(1, 2): 'note'}):
            w = World(limits=[])
            writer = w.open()
            c = w.cancel(w.clock)
            try:
                writer.add({**c, **beside})
            except Exception:
                pass
            r = writer.act(order(1), lambda: 'ordered')
            self.assertFalse(r['done'], beside)

    def test_a_read_only_mapping_is_an_object(self):
        w = World(limits=[])
        writer = w.open()
        c = w.cancel(w.clock)
        writer.add(types.MappingProxyType(c))
        self.assertFalse(writer.act(order(1), lambda: 'ordered')['done'])


class TheOtherSide(unittest.TestCase):
    def test_an_error_that_is_not_an_exception_leaves_a_one_sided_stub(self):
        for error in (asyncio.CancelledError, SystemExit, KeyboardInterrupt):
            w = World(limits=[])
            writer = w.open()

            def countersign(stub, error=error):
                raise error()

            r = writer.act(order(10), lambda: 'ordered', {'countersign': countersign})
            self.assertTrue(r['done'])
            self.assertFalse(r['stub']['countersignature']['accepted'])
            self.assertEqual(writer.book().count('"stub"'), 1)


class TheBookAndWhatIsHeldTogether(unittest.TestCase):
    def test_snapshot_never_loses_a_cancellation_between_the_two(self):
        for _ in range(10):
            w = World(limits=[])
            t = {'now': w.clock}
            writer = w.open(now=lambda: t['now'])
            c = w.cancel(w.clock + 2 * HOUR)
            try:
                writer.add(c)
            except Exception:
                pass
            t['now'] = w.clock + 3 * HOUR
            kept = {}
            go = threading.Event()

            def keeper():
                go.wait()
                kept['pair'] = writer.snapshot()

            k = threading.Thread(target=keeper)
            k.start()
            go.set()
            writer.act(order(1), lambda: None)
            k.join()
            book, held = kept['pair']
            payload = c['cancellation']['payload']
            self.assertTrue(payload in book or any(h['cancellation']['payload'] == payload for h in held))
            again = open_recorder(book, w.slip_fingerprint, w.agent, w.issuer_keys, options={'cancellations': held}, now=lambda: t['now'])
            self.assertFalse(again.act(order(1), lambda: 'ordered')['done'])

    def test_snapshot_from_inside_an_action_reads_at_once(self):
        w = World(limits=[])
        writer = w.open()
        seen = {}
        writer.act(order(1), lambda: seen.setdefault('pair', writer.snapshot()))
        self.assertEqual(seen['pair'][0], w.book())


class ValuesPythonHas(unittest.TestCase):
    def test_a_number_too_large_for_a_float_is_no_time(self):
        w = World(limits=[])
        writer = w.open(now=lambda: 10**400)
        with self.assertRaises(Exception) as raised:
            writer.act(order(1), lambda: 'ordered')
        self.assertEqual(getattr(raised.exception, 'code', None), 'bad-field')

    def test_options_holding_objects_that_cannot_be_copied_are_answered(self):
        w = World(limits=[])
        for odd in (threading.Lock(), (x for x in ()), object()):
            result = check_book(w.book(), {'issuerKeys': w.issuer_keys, 'vouchers': odd})
            self.assertIn('summary', result)

    def test_a_dated_time_is_written_as_a_javascript_date_is(self):
        import datetime

        moment = datetime.datetime(2026, 10, 5, 10, 0, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual(format_time(moment), '2026-10-05T10:00:00Z')
        with self.assertRaises(ValueError):
            format_time(datetime.datetime(2026, 10, 5, 10, 0, 0))
        with self.assertRaises(ValueError):
            format_time('2026-10-05T10:00:00Z')


if __name__ == '__main__':
    unittest.main()
