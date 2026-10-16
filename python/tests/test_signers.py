# Signers: a key held elsewhere (a key service, a hardware module) that
# signs on request. Wherever "private_keys" is taken, each item may be a key
# or a signer. A record made through signers is the same record; a signer
# that fails in any way leaves no record, and the error names the method
# and the key. The JavaScript library holds the same rules
# (test/signers.test.mjs).

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ed448
import threading
import time
import unittest

from test_recorder import HOUR, START, World, order

from provared import (
    Refusal,
    Signer,
    check_book,
    countersign,
    entry_line,
    from_base64url,
    generate_key_set,
    signer_from_key,
    thumbprint,
    write_acknowledgement,
    write_book,
    write_pass,
    write_refusal,
    write_stub,
    write_terms,
    write_vouching,
    write_withdrawal,
)
from provared.dev import development_recorder
from provared.encoding import from_utf8
from provared.jws import signing_input
from provared.keys import SEAL_METHODS
from provared.seal import write_seal
from provared.signatures import signing_keys, verify_signature
from provared.stub import sign_with_key_set

ORDER = 'supplies.order'
FP = 'A' * 43
ID = 'B' * 21 + 'A'
STUB = {'slip': FP, 'after': None, 'action': ORDER, 'when': START, 'id': ID}
SLH_KEY = {'alg': 'SLH-DSA-SHA2-256s', 'kty': 'AKP', 'pub': 'A' * 86}


def real(keys, private_keys, i):
    return signer_from_key(keys[i]['alg'], private_keys[i], keys[i])


def as_signers(keys, private_keys):
    return [real(keys, private_keys, i) for i in range(len(keys))]


class Remote:
    """A signer as a key service's adaptor would be: any object with "key" and "sign"."""

    def __init__(self, key, sign):
        self.key = key
        self._sign = sign

    def sign(self, data):
        return self._sign(data)


def verifies(test, record, keys):
    for i, s in enumerate(record['signatures']):
        test.assertEqual(verify_signature(keys[i], from_base64url(s['signature']), signing_input(s['protected'], record['payload'])), 'valid', f'signature {i}')


def same_record(test, a, b):
    # The same content and labels, and the same Ed25519 signature, which is
    # deterministic (RFC 8032). ML-DSA-87 signatures are made afresh each
    # time (FIPS 204, hedged), with a key or through a signer.
    test.assertEqual(b['payload'], a['payload'])
    test.assertEqual([s['protected'] for s in b['signatures']], [s['protected'] for s in a['signatures']])
    test.assertEqual(b['signatures'][0]['signature'], a['signatures'][0]['signature'])


class SameRecords(unittest.TestCase):
    def test_every_writer_makes_the_same_record_through_signers_as_with_keys_and_it_checks(self):
        keys, private_keys = generate_key_set()
        signers = as_signers(keys, private_keys)
        self.assertTrue(all(isinstance(s, Signer) for s in signers))
        by = {'keys': keys, 'name': 'Example (invented)'}
        writers = {
            'stub': lambda k: write_stub(STUB, k),
            'refusal': lambda k: write_refusal({'slip': FP, 'by': by, 'action': ORDER, 'reason': 'over-limit', 'when': START, 'id': ID}, k),
            'terms': lambda k: write_terms({'by': by, 'accepts': [ORDER], 'validFrom': '2026-10-01T00:00:00Z', 'validUntil': '2027-10-01T00:00:00Z', 'id': ID}, k),
            'pass': lambda k: write_pass({'slip': FP, 'to': by, 'actions': [ORDER], 'validFrom': '2026-10-05T08:00:00Z', 'validUntil': '2026-10-06T08:00:00Z', 'when': START, 'id': ID}, k),
            'acknowledgement': lambda k: write_acknowledgement({'slip': FP, 'cancellation': FP, 'when': START, 'id': ID}, k),
            'vouching': lambda k: write_vouching({'by': by, 'for': {'kind': 'agent', 'keys': keys, 'name': 'Agent (invented)'}, 'validFrom': '2026-01-01T00:00:00Z', 'validUntil': '2027-01-01T00:00:00Z', 'when': START, 'id': ID}, k),
            'withdrawal': lambda k: write_withdrawal({'vouching': FP, 'when': START, 'id': ID}, k),
        }
        for kind, write in writers.items():
            with_keys = write(private_keys)
            through = write(signers)
            same_record(self, with_keys['record'], through['record'])
            verifies(self, through['record'], keys)
            self.assertEqual(through['fingerprint'], with_keys['fingerprint'], kind)
        stub = write_stub(STUB, private_keys)['record']
        a, b = countersign(stub, private_keys, START), countersign(stub, signers, START)
        same_record(self, a, b)
        verifies(self, b, keys)

    def test_keys_and_signers_may_be_mixed_in_either_order_and_a_signer_may_give_any_bytes_like_value(self):
        keys, private_keys = generate_key_set()
        with_keys = write_stub(STUB, private_keys)['record']
        for mixed in ([real(keys, private_keys, 0), private_keys[1]], (private_keys[0], real(keys, private_keys, 1))):
            record = write_stub(STUB, mixed)['record']
            same_record(self, with_keys, record)
            verifies(self, record, keys)
        for kind in (bytearray, memoryview):
            signer = Remote(keys[0], lambda d, kind=kind: kind(private_keys[0].sign(d)))
            verifies(self, write_stub(STUB, [signer, private_keys[1]])['record'], keys)

    def test_a_signers_two_members_are_read_once(self):
        keys, private_keys = generate_key_set()
        reads = []

        class Once:
            @property
            def key(self):
                reads.append(1)
                if len(reads) > 1:
                    raise RuntimeError('read twice')
                return keys[1]

            def sign(self, data):
                return private_keys[1].sign(data)

        verifies(self, write_stub(STUB, [private_keys[0], Once()])['record'], keys)
        self.assertEqual(len(reads), 1)


def by_signer(test, e, i, alg, key, why):
    test.assertEqual(e.code, 'signature-invalid')
    test.assertTrue(e.message.startswith(f'privateKeys[{i}]: the signer for the {alg} key {thumbprint(key)} '), e.message)
    test.assertRegex(e.message, why)
    test.assertTrue(e.message.endswith('No record was made.'), e.message)


class Refused(unittest.TestCase):
    def setUp(self):
        self.keys, self.private = generate_key_set()

    def refused(self, items):
        with self.assertRaises(Refusal) as caught:
            write_stub(STUB, items)
        return caught.exception

    def test_a_signature_of_the_wrong_length_is_refused_naming_the_method_and_the_key(self):
        k, p = self.keys, self.private
        e = self.refused([Remote(k[0], lambda d: p[0].sign(d)[:63]), p[1]])
        by_signer(self, e, 0, 'Ed25519', k[0], r'gave a signature of 63 bytes, where an Ed25519 signature is 64\.')
        e = self.refused([p[0], Remote(k[1], lambda d: p[1].sign(d)[:4626])])
        by_signer(self, e, 1, 'ML-DSA-87', k[1], r'of 4626 bytes, where an ML-DSA-87 signature is 4627\.')

    def test_a_signature_from_another_key_or_over_other_bytes_is_refused(self):
        k, p = self.keys, self.private
        _, other = generate_key_set()
        why = r'does not check against its key: it holds another key, or signed other bytes\.'
        for signer in (
            Remote(k[0], lambda d: other[0].sign(d)),  # a mistyped key name in a key service's settings
            Remote(k[0], lambda d: p[0].sign(hashlib.sha256(d).digest())),  # a service that signs a fingerprint of the bytes
        ):
            by_signer(self, self.refused([signer, p[1]]), 0, 'Ed25519', k[0], why)
        by_signer(self, self.refused([p[0], Remote(k[1], lambda d: p[1].sign(d + b'\0'))]), 1, 'ML-DSA-87', k[1], why)

    def test_a_signer_that_raises_gives_a_coroutine_or_gives_something_other_than_bytes_is_refused(self):
        k, p = self.keys, self.private
        broken = RuntimeError('the key service is down')

        def down(_):
            raise broken

        e = self.refused([Remote(k[0], down), p[1]])
        by_signer(self, e, 0, 'Ed25519', k[0], r'failed with an error\.')
        self.assertIs(e.__cause__, broken)

        async def coroutine(_):
            return p[0].sign(_)

        by_signer(self, self.refused([Remote(k[0], coroutine), p[1]]), 0, 'Ed25519', k[0], r'gave a coroutine, which was not run')
        for given in ('a' * 64, [1] * 64, 64, None, True, (1,) * 64):
            by_signer(self, self.refused([Remote(k[0], lambda d, given=given: given), p[1]]), 0, 'Ed25519', k[0], r'gave something other than bytes\.')

    def test_anything_that_is_neither_a_key_nor_a_signer_is_refused_in_plain_words(self):
        k, p = self.keys, self.private

        class OnlyKey:
            key = k[0]

        class NoKey:
            def sign(self, data):
                return b''

        for item in ('text', None, 42, {}, {'key': k[0], 'sign': lambda d: b''}, OnlyKey(), NoKey(), k[0]):
            e = self.refused([item, p[1]])
            self.assertEqual(e.code, 'bad-field')
            self.assertTrue(e.message.startswith('privateKeys[0]: must be a private key for Ed25519 (of the package "cryptography"), or a signer'), e.message)
        for items in ('text', None, {0: p[0], 1: p[1]}):
            e = self.refused(items)
            self.assertEqual(e.code, 'bad-field')
            self.assertTrue(e.message.startswith('privateKeys: must be a list'), e.message)
        e = self.refused([p[0]])
        self.assertEqual((e.code, e.message[:16]), ('bad-field', 'privateKeys[1]: '))
        # A key of another method in a place, or of a kind the format does not use, is refused in the same words.
        for item in (p[1], ed448.Ed448PrivateKey.generate()):
            e = self.refused([item, p[1]])
            self.assertEqual(e.code, 'bad-field')
            self.assertTrue(e.message.startswith('privateKeys[0]: must be a private key for Ed25519'), e.message)

        # A list whose items cannot be read is refused, not let through.
        class BadList(list):
            def __getitem__(self, i):
                raise ValueError('no')

        e = self.refused(BadList([p[0], p[1]]))
        self.assertEqual((e.code, e.message), ('bad-field', 'privateKeys[0]: could not be read.'))

    def test_a_signers_key_must_be_exactly_a_key_of_the_method_of_its_place(self):
        k, p = self.keys, self.private
        for key in (k[1], {**k[0], 'kid': 'x'}, {**k[0], 'x': 'A' * 43}, 'text', [k[0]]):
            e = self.refused([Remote(key, lambda d: b''), p[1]])
            self.assertEqual(e.code, 'bad-key')
            self.assertTrue(e.message.startswith('privateKeys[0].key: '), e.message)

    def test_a_writer_that_knows_the_key_a_record_must_be_signed_with_refuses_a_signer_that_holds_another(self):
        k, p = self.keys, self.private
        other_keys, other = generate_key_set()
        by = {'keys': k, 'name': 'Example (invented)'}
        mixed = [real(other_keys, other, 0), p[1]]
        expected = f'privateKeys[0]: the signer holds the Ed25519 key {thumbprint(other_keys[0])}, which is not the key this record must be signed with ({thumbprint(k[0])}).'
        for write in (
            lambda: write_refusal({'slip': FP, 'by': by, 'action': ORDER, 'reason': 'over-limit', 'when': START}, mixed),
            lambda: write_terms({'by': by, 'accepts': [ORDER], 'validFrom': '2026-10-01T00:00:00Z', 'validUntil': '2027-10-01T00:00:00Z'}, mixed),
            lambda: write_vouching({'by': by, 'for': {'kind': 'agent', 'keys': other_keys, 'name': 'A'}, 'validFrom': '2026-01-01T00:00:00Z', 'validUntil': '2027-01-01T00:00:00Z'}, mixed),
        ):
            with self.assertRaises(Refusal) as caught:
                write()
            self.assertEqual((caught.exception.code, caught.exception.message), ('bad-key', expected))

    def test_no_signer_is_asked_for_a_method_this_device_cannot_check_so_no_seal_is_written_in_python(self):
        # "cryptography" has no SLH-DSA: a signer for it is refused before any signer is asked.
        asked = []

        def ask(name):
            def sign(d):
                asked.append(name)
                return bytes(29792)
            return sign

        slh = Remote(SLH_KEY, ask('SLH-DSA'))
        ed = Remote(self.keys[0], ask('Ed25519'))
        with self.assertRaises(Refusal) as caught:
            signing_keys([ed, self.private[1], slh], SEAL_METHODS)
        e = caught.exception
        self.assertEqual(e.code, 'bad-key')
        self.assertEqual(e.message, f'privateKeys[2]: this device does not have SLH-DSA-SHA2-256s built in, so it cannot check a signature from the signer for the SLH-DSA-SHA2-256s key {thumbprint(SLH_KEY)}. No record was made.')
        # write_seal is refused as before, with keys or with signers, and asks no signer.
        by = {'keys': [*self.keys, SLH_KEY], 'name': 'Example recorder (invented)'}
        for items in ([*self.private, slh], [ed, real(self.keys, self.private, 1), slh]):
            with self.assertRaises(RuntimeError):
                write_seal(write_book([{'stub': write_stub(STUB, self.private)['record']}]), {'by': by}, items)
        self.assertEqual(asked, [])

    def test_a_signers_key_is_copied_before_anything_is_signed_so_a_key_changed_by_sign_is_refused(self):
        k, p = self.keys, self.private
        other_keys, other = generate_key_set()

        class Changing:
            def __init__(self):
                self.key = dict(k[0])

            def sign(self, data):
                self.key['x'] = other_keys[0]['x']  # from now on the key it shows is another
                return other[0].sign(data)

        by = {'keys': k, 'name': 'Example (invented)'}
        with self.assertRaises(Refusal) as caught:
            write_terms({'by': by, 'accepts': [ORDER], 'validFrom': '2026-10-01T00:00:00Z', 'validUntil': '2027-10-01T00:00:00Z'}, [Changing(), p[1]])
        by_signer(self, caught.exception, 0, 'Ed25519', k[0], r'does not check against its key')

    def test_a_signers_key_must_be_plain_data_so_no_text_can_say_it_equals_another_key(self):
        k, p = self.keys, self.private
        other_keys, other = generate_key_set()

        class Liar(str):
            """Text that says it equals anything."""

            def __eq__(self, other):
                return True

            def __ne__(self, other):
                return False

            __hash__ = str.__hash__

        class Dict(dict):
            pass

        liar = {**k[0], 'x': Liar(other_keys[0]['x'])}  # shows another key, and says it is this one
        signer = Remote(liar, lambda d: other[0].sign(d))
        by = {'keys': k, 'name': 'Example (invented)'}
        plain = ('bad-key', 'privateKeys[0].key: must be a public key, as plain data.')
        for write in (
            lambda items: write_refusal({'slip': FP, 'by': by, 'action': ORDER, 'reason': 'over-limit', 'when': START}, items),
            lambda items: write_terms({'by': by, 'accepts': [ORDER], 'validFrom': '2026-10-01T00:00:00Z', 'validUntil': '2027-10-01T00:00:00Z'}, items),
            lambda items: write_vouching({'by': by, 'for': {'kind': 'agent', 'keys': other_keys, 'name': 'A'}, 'validFrom': '2026-01-01T00:00:00Z', 'validUntil': '2027-01-01T00:00:00Z'}, items),
            lambda items: write_stub(STUB, items),
        ):
            for key in (liar, {Liar('x'): k[0]['x'], 'alg': 'Ed25519', 'crv': 'Ed25519', 'kty': 'OKP'}, Dict(k[0])):
                with self.assertRaises(Refusal) as caught:
                    write([Remote(key, signer.sign), p[1]])
                self.assertEqual((caught.exception.code, caught.exception.message), plain)
        for key in (liar, Dict(k[0])):
            with self.assertRaises(Refusal) as caught:
                signer_from_key('Ed25519', p[0], key)
            self.assertEqual((caught.exception.code, caught.exception.message), ('bad-key', 'key: must be a public key, as plain data.'))
        # And where the key "by" names holds such text, a signer for another key is still told apart from it.
        liar_by = {'keys': [{**k[0], 'x': Liar(k[0]['x'])}, k[1]], 'name': 'Example (invented)'}
        with self.assertRaises(Refusal) as caught:
            write_refusal({'slip': FP, 'by': liar_by, 'action': ORDER, 'reason': 'over-limit', 'when': START}, [real(other_keys, other, 0), p[1]])
        self.assertEqual(caught.exception.code, 'bad-key')
        # The stub writer refuses such a signer when it is opened.
        w = World()
        with self.assertRaises(Refusal) as caught:
            w.open(private_keys=[Remote({**w.agent_keys[0], 'x': Liar(other_keys[0]['x'])}, lambda d: other[0].sign(d)), w.agent[1]])
        self.assertEqual((caught.exception.code, caught.exception.message), plain)

    def test_signer_from_key_takes_only_a_private_key_of_the_method_it_names_with_its_public_key(self):
        k, p = self.keys, self.private
        self.assertEqual(real(k, p, 0).key, k[0])
        for alg, private, key, code in (
            ('ES256', p[0], k[0], 'bad-field'),
            ('Ed25519', p[1], k[0], 'bad-field'),
            ('ML-DSA-87', p[0], k[1], 'bad-field'),
            ('Ed25519', 'text', k[0], 'bad-field'),
            ('Ed25519', p[0], k[1], 'bad-key'),
            ('Ed25519', p[0], 'text', 'bad-key'),
        ):
            with self.assertRaises(Refusal) as caught:
                signer_from_key(alg, private, key)
            self.assertEqual(caught.exception.code, code, (alg, key))
        with self.assertRaises(RuntimeError):
            signer_from_key('SLH-DSA-SHA2-256s', p[0], SLH_KEY)
        # A public key that does not belong to the private key: every signature is refused.
        _, other = generate_key_set()
        self.assertEqual(self.refused([signer_from_key('Ed25519', other[0], k[0]), p[1]]).code, 'signature-invalid')


def shape_of(r):
    """What a check says, without the fingerprints that differ from one world to another."""
    return {
        'summary': r['summary'],
        'entries': [
            {
                'kind': e['kind'],
                'problems': [x['code'] for x in e['problems']],
                'breaches': [x['code'] for x in e['breaches']],
                'signatures': [s['state'] for s in e.get('signatures') or []],
                'countersignature': (e.get('countersignature') or {}).get('state'),
            }
            for e in r['entries']
        ],
    }


class StubWriter(unittest.TestCase):
    def test_the_same_run_through_signers_gives_the_same_record_and_the_writers_view_is_the_whole_checks(self):
        def run(use_signers):
            w = World()
            if use_signers:
                w.agent = as_signers(w.agent_keys, w.agent)
            service = as_signers(w.service_keys, w.service) if use_signers else w.service
            writer = w.open()
            outcomes = [writer.act(order(150), lambda: 1, {'countersign': lambda stub: countersign(stub, service, w.clock + 1000)})['done']]
            w.clock += HOUR
            outcomes.append(writer.act(order(60), lambda: 2)['done'])
            outcomes.append(writer.record(order(60))['seq'])
            w.clock += HOUR
            outcomes.append(bool(writer.add(w.cancel(w.clock - 1000)).get('acknowledgement')))
            w.clock += HOUR
            outcomes.append(writer.act(order(1), lambda: 3)['done'])
            whole = check_book(writer.book(), issuer_keys=w.issuer_keys)
            self.assertEqual(writer.check(), whole)
            return outcomes, shape_of(whole)

        with_keys = run(False)
        through = run(True)
        self.assertEqual(with_keys[0], [True, False, 1, True, False])
        self.assertEqual(through, with_keys)
        self.assertFalse(through[1]['summary']['problemFound'])
        self.assertEqual([e['kind'] for e in through[1]['entries']], ['slip', 'stub', 'stub', 'cancellation', 'acknowledgement'])

    def test_a_book_written_through_signers_checks_exactly_as_the_same_book_written_with_keys(self):
        w = World()
        writer = w.open()
        self.assertTrue(writer.act(order(150), lambda: 1, {'countersign': lambda stub: countersign(stub, w.service, w.clock)})['done'])
        w.clock += HOUR
        writer.record(order(60))
        w.clock += HOUR
        writer.add(w.cancel(w.clock - 1000))
        book = writer.book()
        sets = [(w.agent_keys, w.agent), (w.service_keys, w.service)]
        kinds = ('stub', 'countersignature', 'acknowledgement')
        lines = []
        signed_again = 0
        for line in book.strip('\n').split('\n'):
            entry = json.loads(line)
            for kind in kinds:
                if kind not in entry:
                    continue
                record = entry[kind]
                s = record['signatures'][0]
                keys, private = next(pair for pair in sets if verify_signature(pair[0][0], from_base64url(s['signature']), signing_input(s['protected'], record['payload'])) == 'valid')
                content = json.loads(from_utf8(from_base64url(record['payload'])))
                made, _ = sign_with_key_set(kind, content, as_signers(keys, private))
                same_record(self, record, made)
                entry[kind] = made
                signed_again += 1
            lines.append(entry_line(entry))
        self.assertEqual(signed_again, 4)
        a = check_book(book, issuer_keys=w.issuer_keys)
        b = check_book('\n'.join(lines) + '\n', issuer_keys=w.issuer_keys)
        self.assertNotEqual(b['root'], a['root'])  # the lines hold other ML-DSA-87 signatures
        self.assertEqual({**b, 'root': None}, {**a, 'root': None})
        self.assertFalse(a['summary']['problemFound'])

    def test_a_signer_that_fails_leaves_nothing_written_and_the_writers_view_stays_exact(self):
        w = World()
        state = {'failing': True}
        broken = RuntimeError('the key service is down')

        def sign(d):
            if state['failing']:
                raise broken
            return w.agent[1].sign(d)

        writer = w.open(private_keys=[w.agent[0], Remote(w.agent_keys[1], sign)])
        book = writer.book()
        taken = []
        out = writer.act(order(10), lambda: taken.append(1))
        self.assertFalse(out['done'])
        self.assertEqual(taken, [])
        self.assertEqual(out['answer']['problems'][-1], {'code': 'signature-invalid', 'message': f'privateKeys[1]: the signer for the ML-DSA-87 key {thumbprint(w.agent_keys[1])} failed with an error. No record was made.'})
        with self.assertRaises(Refusal) as caught:
            writer.record(order(10))
        self.assertIs(caught.exception.__cause__, broken)
        self.assertEqual(writer.book(), book)
        self.assertEqual(writer.check(), check_book(book, issuer_keys=w.issuer_keys))
        state['failing'] = False
        self.assertEqual(writer.act(order(10), lambda: taken.append(1))['stub']['seq'], 0)
        self.assertEqual(writer.check(), check_book(writer.book(), issuer_keys=w.issuer_keys))

    def test_a_signer_that_never_answers_is_given_sign_within_then_nothing_is_written_and_the_writer_goes_on(self):
        w = World()
        state = {'mode': 'hang'}
        release = threading.Event()
        late = []

        def sign(d):
            if state['mode'] == 'hang':
                release.wait(10)
                return w.agent[1].sign(d)
            if state['mode'] == 'late':
                time.sleep(0.3)
                late.append(1)
                return w.agent[1].sign(d)
            return w.agent[1].sign(d)

        writer = w.open(private_keys=[w.agent[0], Remote(w.agent_keys[1], sign)], sign_within=100)
        book = writer.book()
        started = time.monotonic()
        out = writer.act(order(10), lambda: 'taken')
        self.assertFalse(out['done'])
        self.assertEqual(out['answer']['problems'][-1], {'code': 'signature-invalid', 'message': f'privateKeys[1]: the signer for the ML-DSA-87 key {thumbprint(w.agent_keys[1])} gave no answer within 100 milliseconds. No record was made.'})
        self.assertLess(time.monotonic() - started, 5)
        # The writer's turn was let go: the next call is answered.
        self.assertTrue(writer.before(order(10))['allowed'])
        release.set()
        # A late answer is not used.
        state['mode'] = 'late'
        with self.assertRaises(Refusal) as caught:
            writer.record(order(10))
        self.assertRegex(caught.exception.message, 'gave no answer within 100 milliseconds')
        time.sleep(0.5)
        self.assertEqual(late, [1])
        self.assertEqual(writer.book(), book)
        self.assertEqual(writer.check(), check_book(book, issuer_keys=w.issuer_keys))
        state['mode'] = 'answer'
        self.assertEqual(writer.act(order(10), lambda: 'taken')['stub']['seq'], 0)
        for sign_within in (0, -1, float('nan'), 2**31, '100', float('inf')):
            with self.assertRaises(Refusal) as caught:
                w.open(sign_within=sign_within)
            self.assertTrue(caught.exception.message.startswith('signWithin: '))
        # The development stub writer passes it on too.
        with self.assertRaises(Refusal) as caught:
            development_recorder({'actions': [ORDER]}, {'sign_within': 0})
        self.assertTrue(caught.exception.message.startswith('signWithin: '))

    def test_a_signer_that_calls_the_writer_is_refused_at_once_as_an_action_is(self):
        w = World()
        holder = {}

        def sign(d):
            holder['writer'].before(order(1))
            return w.agent[1].sign(d)

        holder['writer'] = writer = w.open(private_keys=[w.agent[0], Remote(w.agent_keys[1], sign)], sign_within=4000)
        started = time.monotonic()
        with self.assertRaises(Refusal) as caught:
            writer.record(order(10))
        self.assertEqual(caught.exception.code, 'signature-invalid')
        self.assertIn('called from inside an action', str(caught.exception.__cause__))
        self.assertLess(time.monotonic() - started, 2, 'refused at once, not after sign_within')

    def test_the_writer_refuses_when_it_is_opened_a_signer_that_holds_another_key_than_its_agents(self):
        w = World()
        other_keys, other = generate_key_set()
        with self.assertRaises(Refusal) as caught:
            w.open(private_keys=[real(other_keys, other, 0), w.agent[1]])
        self.assertEqual(caught.exception.code, 'bad-key')
        self.assertEqual(caught.exception.message, f'privateKeys[0]: the signer holds the Ed25519 key {thumbprint(other_keys[0])}, which is not the key this record must be signed with ({thumbprint(w.agent_keys[0])}).')
        with self.assertRaises(Refusal) as caught:
            w.open(private_keys=['text', w.agent[1]])
        self.assertEqual(caught.exception.code, 'bad-field')

    def test_a_helper_under_a_pass_signs_with_the_keys_the_pass_names_not_the_slips_agents(self):
        w = World(passes=1)
        helper_keys, helper = generate_key_set()
        made = write_pass({'slip': w.slip_fingerprint, 'to': {'keys': helper_keys, 'name': 'Helper agent'}, 'actions': [ORDER], 'limits': [],
                           'validFrom': '2026-10-05T08:00:00Z', 'validUntil': '2026-10-12T08:00:00Z', 'when': START}, w.agent)
        book = write_book([{'slip': w.slip}, {'pass': made['record']}])
        under = {'book': book, 'pass_': made['fingerprint']}
        with self.assertRaises(Refusal) as caught:
            w.open(private_keys=as_signers(w.agent_keys, w.agent), **under)
        self.assertEqual(caught.exception.code, 'bad-key')
        self.assertIn(f'({thumbprint(helper_keys[0])})', caught.exception.message)
        writer = w.open(private_keys=as_signers(helper_keys, helper), **under)
        out = writer.act(order(10), lambda: 'taken', {'countersign': lambda stub: countersign(stub, w.service, w.clock)})
        self.assertTrue(out['done'])
        self.assertFalse(check_book(writer.book(), issuer_keys=w.issuer_keys)['summary']['problemFound'])


if __name__ == '__main__':
    unittest.main()
