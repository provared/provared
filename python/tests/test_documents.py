# The reserved document names, the fingerprints they stand for, and
# "details_after": a receipt bound to the platform's own identifier for the
# call (format description, section 27). The shared test files
# (http-fingerprints.json, recorder-details-after.json, stub-contents.json)
# show that both languages give the same answers; here, what only the
# Python version has to show: bytes of other kinds, both names of the
# option, a function that gives a coroutine, and the time limit.

import base64
import hashlib
import json
import time
import unittest

from test_recorder import START, World, order

from provared import (
    DOCUMENT_NAMES,
    RESERVED_DOCUMENT_PREFIX,
    Refusal,
    check_before,
    format_time,
    http_request_fingerprint,
    http_response_fingerprint,
    identifier_fingerprint,
    prepare_approval,
    write_stub,
)


def _sha(text):
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode('utf-8')).digest()).rstrip(b'=').decode('ascii')


def _content(record):
    payload = record['payload']
    return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))


FP = 'A' * 43
EVENT = {'name': 'provared.event-id', 'sha256': FP}


class Fingerprints(unittest.TestCase):
    def test_the_list_is_fixed(self):
        self.assertEqual(RESERVED_DOCUMENT_PREFIX, 'provared.')
        self.assertEqual(len(DOCUMENT_NAMES), 7)
        with self.assertRaises(TypeError):
            DOCUMENT_NAMES['provared.invoice'] = 'x'

    def test_a_body_may_be_any_kind_of_bytes_and_text_is_refused(self):
        body = b'{"hello": "world"}'
        r = {'method': 'POST', 'url': 'https://example.com/foo?param=Value&Pet=dog'}
        want = http_request_fingerprint({**r, 'body': body})
        self.assertEqual(want, _sha('"@method": POST\n"@target-uri": https://example.com/foo?param=Value&Pet=dog\n"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n"@signature-params": ("@method" "@target-uri" "content-digest")'))
        self.assertEqual(http_request_fingerprint({**r, 'body': bytearray(body)}), want)
        self.assertEqual(http_request_fingerprint({**r, 'body': memoryview(body)}), want)
        self.assertEqual(http_response_fingerprint({'status': 200, 'body': body}), http_response_fingerprint({'status': 200, 'body': bytearray(body)}))
        for wrong in ('text', 5, ['a']):
            with self.assertRaises(Refusal):
                http_request_fingerprint({**r, 'body': wrong})
        # True is not a status, though Python counts it as a whole number.
        with self.assertRaises(Refusal):
            http_response_fingerprint({'status': True})

    def test_none_is_no_body_and_a_status_is_a_whole_number_whatever_its_type(self):
        r = {'method': 'POST', 'url': 'https://example.com/'}
        self.assertEqual(http_request_fingerprint({**r, 'body': None}), http_request_fingerprint(r))
        self.assertEqual(http_response_fingerprint({'status': 404, 'body': None}), http_response_fingerprint({'status': 404}))
        # A float that equals a whole number is that number, as in JavaScript.
        self.assertEqual(http_response_fingerprint({'status': 200.0}), http_response_fingerprint({'status': 200}))
        for wrong in (200.5, float('inf'), float('nan'), True, False, 99.0, 600):
            with self.assertRaises(Refusal):
                http_response_fingerprint({'status': wrong})

    def test_a_subclass_s_own_way_of_writing_itself_is_never_used(self):
        class Status(int):
            def __str__(self):
                return '999'

            __repr__ = __str__

            def __format__(self, spec):
                return '999'

            def __index__(self):
                return 999

            def __int__(self):
                return 999

        class Text(str):
            def __str__(self):
                return 'POST'

            def __format__(self, spec):
                return 'POST'

            def encode(self, *args, **kwargs):
                return b'other'

        class Body(bytes):
            def __bytes__(self):
                return b'other'

        self.assertEqual(http_response_fingerprint({'status': Status(200)}), http_response_fingerprint({'status': 200}))
        self.assertEqual(
            http_request_fingerprint({'method': Text('GET'), 'url': Text('https://example.com/'), 'body': Body(b'{}')}),
            http_request_fingerprint({'method': 'GET', 'url': 'https://example.com/', 'body': b'{}'}),
        )
        self.assertEqual(identifier_fingerprint(Text('evt-1')), identifier_fingerprint('evt-1'))

    def test_an_identifier_is_fingerprinted_exactly_as_given(self):
        self.assertEqual(identifier_fingerprint('toolu_01AbC'), _sha('toolu_01AbC'))
        for wrong in ('', 'a\ud800', 42, None, b'abc'):
            with self.assertRaises(Refusal):
                identifier_fingerprint(wrong)

    def test_a_reserved_name_not_on_the_list_is_refused_in_a_stub_and_beforehand(self):
        w = World()
        with self.assertRaises(Refusal) as e:
            write_stub({'slip': w.slip_fingerprint, 'after': None, 'action': 'supplies.order', 'details': [{'name': 'provared.invoice', 'sha256': FP}]}, w.agent)
        self.assertEqual(e.exception.code, 'bad-field')
        answer = check_before(w.book(), {'slip': w.slip_fingerprint, **order(1), 'details': [{'name': 'provared.invoice', 'sha256': FP}]}, issuer_keys=w.issuer_keys)
        self.assertEqual([p['code'] for p in answer['problems']], ['bad-field'])
        # Only the three identifiers may be named more than once.
        twice = [{'name': 'provared.arguments', 'sha256': FP}] * 2
        answer = check_before(w.book(), {'slip': w.slip_fingerprint, **order(1), 'details': twice}, issuer_keys=w.issuer_keys)
        self.assertEqual([p['code'] for p in answer['problems']], ['bad-field'])
        with self.assertRaises(Refusal):
            prepare_approval({'slip': w.slip_fingerprint, 'action': 'supplies.order', 'details': twice})
        write_stub({'slip': w.slip_fingerprint, 'after': None, 'action': 'supplies.order', 'details': [EVENT, EVENT]}, w.agent)


class DetailsAfter(unittest.TestCase):
    def test_both_names_of_the_option_are_taken_and_the_stub_keeps_its_starting_time(self):
        w = World()
        writer = w.open()
        for name in ('details_after', 'detailsAfter'):

            def perform():
                w.clock += 60 * 1000
                return {'id': 'evt-1'}

            began = w.clock
            r = writer.act(order(1), perform, {name: lambda result: [{'name': 'provared.event-id', 'sha256': identifier_fingerprint(result['id'])}]})
            self.assertEqual(r['detailsAfter'], {'added': 1, 'problem': None})
            content = _content(r['stub']['record'])
            self.assertEqual(content['details'], [{'name': 'provared.event-id', 'sha256': identifier_fingerprint('evt-1')}])
            self.assertEqual(content['when'], format_time(began))
            self.assertNotEqual(began, w.clock)
        self.assertTrue(writer.check()['summary']['intact'])

    def test_the_python_name_is_taken_over_the_javascript_name_when_both_are_given(self):
        w = World()
        writer = w.open()
        r = writer.act(order(1), lambda: 'done', {'details_after': lambda result: [EVENT], 'detailsAfter': lambda result: [EVENT, EVENT]})
        self.assertEqual(r['detailsAfter'], {'added': 1, 'problem': None})

    def test_an_exception_that_is_not_an_error_ends_the_wait_at_once(self):
        w = World()
        writer = w.open(countersign_within=20000)
        for raised in (SystemExit, KeyboardInterrupt, GeneratorExit):

            def later(result, raised=raised):
                raise raised()

            started = time.monotonic()
            r = writer.act(order(1), lambda: 'done', {'details_after': later})
            self.assertLess(time.monotonic() - started, 5, 'answered at once, not at the time limit')
            self.assertTrue(r['done'])
            self.assertEqual(r['detailsAfter']['problem']['code'], 'details-not-added')

    def test_where_the_second_signing_fails_the_stub_made_before_is_written_and_the_answer_says_so(self):
        from provared import signer_from_key

        w = World()
        asked = [0]
        failing = [False]

        class Failing:
            def __init__(self, inner):
                self.inner = inner
                self.key = inner.key

            def sign(self, data):
                asked[0] += 1
                if failing[0] and asked[0] > 2:
                    raise RuntimeError('the key service is down')
                return self.inner.sign(data)

        signers = [Failing(signer_from_key(alg, key, public)) for alg, key, public in zip(('Ed25519', 'ML-DSA-87'), w.agent, w.agent_keys)]
        writer = w.open(private_keys=signers)
        failing[0] = True
        r = writer.act(order(1), lambda: 'done', {'details_after': lambda result: [EVENT]})
        self.assertTrue(r['done'])
        self.assertEqual(r['detailsAfter'], {
            'added': 0,
            'problem': {'code': 'details-not-added', 'message': 'The stub with the further documents could not be made or signed, so the stub made before the action was written, without them.'},
        })
        self.assertNotIn('details', _content(r['stub']['record']))
        self.assertTrue(writer.check()['summary']['intact'])

    def test_a_coroutine_or_too_long_a_wait_leaves_the_stub_without_further_documents(self):
        w = World()
        writer = w.open(countersign_within=40)

        async def later(result):
            return [EVENT]

        def slow(result):
            import time

            time.sleep(0.5)
            return [EVENT]

        for function in (later, slow):
            r = writer.act(order(1), lambda: 'done', {'details_after': function})
            self.assertTrue(r['done'])
            self.assertEqual(r['detailsAfter']['added'], 0)
            self.assertEqual(r['detailsAfter']['problem']['code'], 'details-not-added')
            self.assertNotIn('details', _content(r['stub']['record']))

    def test_what_it_gave_is_copied_once_so_a_value_that_changes_from_one_reading_to_the_next_cannot_slip_in(self):
        class Shifting(dict):
            """Each reading of "sha256" by name gives another value."""

            reads = 0

            def __getitem__(self, name):
                if name == 'sha256':
                    Shifting.reads += 1
                    return FP if Shifting.reads == 1 else 'short'
                return dict.__getitem__(self, name)

        w = World()
        writer = w.open()
        r = writer.act(order(1), lambda: 'done', {'details_after': lambda result: [Shifting(name='provared.event-id', sha256=FP)]})
        self.assertEqual(r['detailsAfter'], {'added': 1, 'problem': None})
        self.assertEqual(_content(r['stub']['record'])['details'], [EVENT])

    def test_a_call_to_the_writer_from_inside_it_is_refused_at_once(self):
        w = World()
        writer = w.open()
        inner = []

        def later(result):
            try:
                writer.book()
                writer.act(order(1), lambda: 'again')
                inner.append('ran')
            except Exception as e:  # noqa: BLE001
                inner.append(str(e))
            return [EVENT]

        r = writer.act(order(1), lambda: 'done', {'details_after': later})
        self.assertIn('inside an action', inner[0])
        self.assertEqual(r['detailsAfter']['added'], 1)

    def test_with_an_approval_the_action_is_not_taken(self):
        w = World(requires=[{'above': 50, 'action': 'supplies.order', 'need': 'approval', 'unit': 'GBP'}])
        writer = w.open()
        approval = w.approve(order(60), START)
        taken = []
        r = writer.act(order(60), lambda: taken.append(1), {'approval': approval, 'details_after': lambda result: []})
        self.assertFalse(r['done'])
        self.assertEqual(taken, [])
        self.assertEqual([p['code'] for p in r['answer']['problems']], ['bad-field'])


if __name__ == '__main__':
    unittest.main()
