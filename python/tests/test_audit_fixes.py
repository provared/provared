# The fixes that the audit of the Internet-Draft (24 October 2026) listed for
# version 0.6.0, in the Python version. Each refusal here fails without its
# fix. Where the library beneath (OpenSSL) would refuse the same bytes on its
# own, the test stands a yes-saying key in its place, so that it shows this
# library deciding for itself, as the format description asks (section 3.8).

import json
import pathlib
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

import provared.signatures as signatures
import provared.timestamp as timestamp
from provared.der import Element, read_element, set_in_order, time_of, validate_der
from provared.encoding import Refusal, from_base64url, to_base64url
from provared.keys import bad_ed25519_signature, check_key, on_p256
from provared.signatures import generate_key_set, sign, verify_signature
from provared.timestamp import check_stamp

VECTORS = pathlib.Path(__file__).resolve().parents[2] / 'test-vectors'

# The order L of the Ed25519 base point (RFC 8032, section 5.1).
L = 2**252 + 27742317777372353535851937790883648493


def s_of(signature):
    return int.from_bytes(signature[32:], 'little')


def with_s(signature, s):
    """The same signature with its number S replaced, the point R kept."""
    return bytes(signature[:32]) + (s % (1 << 256)).to_bytes(32, 'little')


class YesSayingKey(ed25519.Ed25519PublicKey):
    """A key whose "verify" accepts everything: only this library's own checks can refuse."""

    def public_bytes(self, encoding, format):
        return bytes(32)

    def public_bytes_raw(self):
        return bytes(32)

    def verify(self, signature, data):
        return None

    def __eq__(self, other):
        return self is other

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def stamp_case(name):
    """A case of the shared test file for time-stamps, by name: its token, what was stamped and its options."""
    data = json.loads((VECTORS / 'stamps.json').read_text(encoding='utf-8'))
    for c in data['cases']:
        if c['name'] == name:
            return from_base64url(c['token']), from_base64url(c['stamped']), c.get('options')
    raise KeyError(name)


def shared_case(file, name):
    """A case of a shared test file, by name."""
    data = json.loads((VECTORS / file).read_text(encoding='utf-8'))
    for c in data['cases']:
        if c['name'] == name:
            return c
    raise KeyError(name)


class BitStrings(unittest.TestCase):
    def test_a_bit_string_whose_unused_bits_are_not_zero_is_not_strict_der(self):
        # X.690, sections 8.6.2 and 11.2.1: the first byte counts the unused bits
        # of the last, 0 to 7; a string of no bits has none; the unused bits are zero.
        def check(hex_text):
            data = bytes.fromhex(hex_text)
            validate_der(data, read_element(data, 0))

        for bad in ('030201ff', '030207ff', '030101', '0303030004'):
            with self.assertRaises(Refusal, msg=bad) as caught:
                check(bad)
            self.assertEqual(caught.exception.code, 'stamp-bad-data', bad)
        for good in ('030200ff', '030201fe', '03020780', '030100', '0303030008'):
            check(good)


class P256Keys(unittest.TestCase):
    def test_a_key_that_is_not_a_point_on_the_curve_is_refused_as_bad_key_before_any_signature_is_tried(self):
        numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        genuine = {
            'alg': 'ES256',
            'crv': 'P-256',
            'kty': 'EC',
            'x': to_base64url(numbers.x.to_bytes(32, 'big')),
            'y': to_base64url(numbers.y.to_bytes(32, 'big')),
        }
        self.assertEqual(check_key(genuine, ['ES256'], 'key'), 'ES256')
        # The base point of P-256 (FIPS 186-5, section D.1.2.3) is on the curve.
        base = {
            **genuine,
            'x': to_base64url(bytes.fromhex('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296')),
            'y': to_base64url(bytes.fromhex('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')),
        }
        self.assertEqual(check_key(base, ['ES256'], 'key'), 'ES256')

        def changed(text):
            data = bytearray(from_base64url(text))
            data[31] ^= 1
            return to_base64url(bytes(data))

        prime = to_base64url(bytes.fromhex('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'))
        for name, key in (
            ('y changed', {**genuine, 'y': changed(genuine['y'])}),
            ('x changed', {**genuine, 'x': changed(genuine['x'])}),
            ('filler bytes', {**genuine, 'x': to_base64url(bytes([1] * 32)), 'y': to_base64url(bytes([2] * 32))}),
            ('x equal to the prime', {**genuine, 'x': prime}),
            ('y equal to the prime', {**genuine, 'y': prime}),
        ):
            with self.assertRaises(Refusal, msg=name) as caught:
                check_key(key, ['ES256'], 'key')
            self.assertEqual(caught.exception.code, 'bad-key', name)
            self.assertIn('point on the curve', caught.exception.message, name)
        self.assertTrue(on_p256(from_base64url(genuine['x']), from_base64url(genuine['y'])))
        self.assertFalse(on_p256(from_base64url(genuine['x']), from_base64url(changed(genuine['y']))))
        # A second written form of one point, a half written as itself plus the
        # prime, is refused and not reduced: the point with x = 5, and the point
        # with y = 5 (its x found by solving the curve's equation), each as itself
        # and with that half written as 5 + p. Both halves of 5 + p fit 32 bytes.
        five = to_base64url(bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000005'))
        five_plus_p = to_base64url(bytes.fromhex('ffffffff00000001000000000000000000000001000000000000000000000004'))
        y_of_x5 = to_base64url(bytes.fromhex('459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc'))
        x_of_y5 = to_base64url(bytes.fromhex('d7325d7646cd60d80a92738ceb345f844cffaf35841022cab176f692de8de1d7'))
        self.assertEqual(check_key({**genuine, 'x': five, 'y': y_of_x5}, ['ES256'], 'key'), 'ES256')
        self.assertEqual(check_key({**genuine, 'x': x_of_y5, 'y': five}, ['ES256'], 'key'), 'ES256')
        for name, key in (
            ('x written as 5 plus the prime', {**genuine, 'x': five_plus_p, 'y': y_of_x5}),
            ('y written as 5 plus the prime', {**genuine, 'x': x_of_y5, 'y': five_plus_p}),
        ):
            with self.assertRaises(Refusal, msg=name) as caught:
                check_key(key, ['ES256'], 'key')
            self.assertEqual(caught.exception.code, 'bad-key', name)
            self.assertIn('point on the curve', caught.exception.message, name)
        for name in ('a P-256 key with x written as 5 plus the prime', 'a P-256 key with y written as 5 plus the prime'):
            self.assertEqual(shared_case('keys.json', name)['expected']['refused']['code'], 'bad-key', name)


class Ed25519Signatures(unittest.TestCase):
    def test_a_signature_whose_s_is_not_below_l_is_refused_by_the_library_itself_whatever_the_device_would_say(self):
        keys, private_keys = generate_key_set()
        message = b'a message'
        genuine = sign('Ed25519', private_keys[0], message)
        self.assertEqual(verify_signature(keys[0], genuine, message), 'valid')
        raised = with_s(genuine, s_of(genuine) + L)
        self.assertFalse(bad_ed25519_signature(genuine))
        self.assertTrue(bad_ed25519_signature(raised))
        self.assertTrue(bad_ed25519_signature(with_s(genuine, L)))
        self.assertFalse(bad_ed25519_signature(with_s(genuine, L - 1)))
        # With a key that says yes to everything, only the library's own check can refuse.
        with mock.patch.object(signatures, '_load', return_value=YesSayingKey()):
            self.assertEqual(verify_signature(keys[0], genuine, message), 'valid')
            self.assertEqual(verify_signature(keys[0], raised, message), 'invalid')
            self.assertEqual(verify_signature(keys[0], with_s(genuine, L), message), 'invalid')
            self.assertEqual(verify_signature(keys[0], with_s(genuine, s_of(genuine) | (1 << 255)), message), 'invalid')
        # On a device without Ed25519 it is not checked, as a signature with a weak R is not.
        self.assertEqual(verify_signature(keys[0], raised, message, ['Ed25519']), 'unavailable')

    def test_an_ed25519_time_stamp_whose_s_is_not_below_l_is_refused_by_the_library_itself(self):
        token, stamped, options = stamp_case('signature: an Ed25519 signature with S raised by L')
        with mock.patch.object(timestamp, '_public_key', return_value=YesSayingKey()):
            with self.assertRaises(Refusal) as caught:
                check_stamp(token, stamped, options)
            self.assertEqual(caught.exception.code, 'stamp-invalid')
            # The same yes-saying key passes a sound time-stamp, so it is the library that refused.
            sound, stamped, options = stamp_case('Ed25519 with SHA-512, as RFC 8419 requires')
            self.assertEqual(check_stamp(sound, stamped, options)['state'], 'valid')


class StrictDer(unittest.TestCase):
    """Added after the independent review of these fixes (24 October 2026)."""

    def check(self, hex_text):
        data = bytes.fromhex(hex_text)
        validate_der(data, read_element(data, 0))

    def test_a_string_written_in_parts_is_not_strict_der(self):
        # X.690, section 10.2: a string of bits, bytes or characters, or a time, is written in one piece.
        for bad in ('2308030200ff030200ff', '2406040101040102', '2c0a0c036162630c03646566', '3811180f32303236313030353132303030305a'):
            with self.assertRaises(Refusal, msg=bad) as caught:
                self.check(bad)
            self.assertEqual(caught.exception.code, 'stamp-bad-data', bad)
            self.assertIn('written in parts', caught.exception.message, bad)
        for name in ('a constructed bit string', 'a constructed octet string', 'a constructed character string', 'a constructed time'):
            self.assertEqual(shared_case('der-strict.json', name)['expected']['refused']['code'], 'stamp-bad-data', name)

    def test_a_set_out_of_der_order_is_not_strict_der(self):
        # X.690, section 11.6: the items of a set in the order of their encodings, compared as bytes; equal items may stand side by side.
        for bad in ('3106020102020101', '310702020100020101', '310a30030201023003020101', '30083106020102020101'):
            with self.assertRaises(Refusal, msg=bad) as caught:
                self.check(bad)
            self.assertEqual(caught.exception.code, 'stamp-bad-data', bad)
            self.assertIn('order DER requires', caught.exception.message, bad)
        # A sequence is not sorted, and a set under a tag that hides its kind cannot be told from one.
        for good in ('3106020101020102', '3106020101020101', '310702010102020100', '310a30030201013003020102', '3006020102020101', 'a006020102020101'):
            self.check(good)
        data = bytes.fromhex('020101020102')
        self.assertTrue(set_in_order(data, [read_element(data, 0), read_element(data, 3)]))
        data = bytes.fromhex('020102020101')
        self.assertFalse(set_in_order(data, [read_element(data, 0), read_element(data, 3)]))
        data = bytes.fromhex('020101020101')
        self.assertTrue(set_in_order(data, [read_element(data, 0), read_element(data, 3)]))
        # Compared as bytes, the shorter padded with zeros: a shorter item is not for that reason the lesser.
        data = bytes.fromhex('0201020005')
        self.assertFalse(set_in_order(data, [Element(2, 0, 2, 2), Element(2, 2, 4, 5)]))
        data = bytes.fromhex('0200050201')
        self.assertTrue(set_in_order(data, [Element(2, 0, 2, 3), Element(2, 3, 5, 5)]))
        # Where no standard requires DER of a set, the walk is told not to hold its order, and holds everything else.
        unordered = bytes.fromhex('3106020102020101')
        with self.assertRaises(Refusal) as caught:
            validate_der(unordered, read_element(unordered, 0))
        self.assertIn('order DER requires', caught.exception.message)
        validate_der(unordered, read_element(unordered, 0), False)
        not_shortest = bytes.fromhex('310702010202020001')
        with self.assertRaises(Refusal) as caught:
            validate_der(not_shortest, read_element(not_shortest, 0), False)
        self.assertIn('shortest form', caught.exception.message)


class TimeStamps(unittest.TestCase):
    def test_the_signed_attributes_must_be_in_der_order_and_the_signed_datas_own_sets_may_be_in_any_order(self):
        for name, words in (
            ('attributes: in another order', 'signed attributes are not in the order'),
        ):
            token, stamped, options = stamp_case(name)
            with self.assertRaises(Refusal, msg=name) as caught:
                check_stamp(token, stamped, options)
            self.assertEqual(caught.exception.code, 'stamp-bad-data', name)
            self.assertIn(words, caught.exception.message, name)
        # Real services list the signing certificate before its issuer (chain order), which is not DER order, and CMS does
        # not require DER of the signed data's own sets (RFC 5652 section 10.2.3): so these pass (the founder's decision
        # of 24 October 2026, after three genuine time-stamps of a public service were refused).
        for name in (
            'attributes: in DER order, written out',
            'certificates: two certificates in DER order, written out',
            'certificates: two certificates out of DER order',
            'wrapper: two fingerprint methods listed',
            'wrapper: two fingerprint methods listed out of DER order',
        ):
            token, stamped, options = stamp_case(name)
            self.assertEqual(check_stamp(token, stamped, options)['state'], 'valid', name)

    def test_an_ed25519_time_stamp_gives_its_methods_no_parameters_as_rfc_8419_requires(self):
        for name, words in (
            ('Ed25519 with SHA-512, the fingerprint method with parameters', 'gives the method parameters, which RFC 8419'),
            ('signing method: Ed25519 named with parameters', 'signing method parameters, which RFC 8419'),
            ('Ed25519 with SHA-256 named by the signer', 'fingerprint method other than SHA-512'),
        ):
            token, stamped, options = stamp_case(name)
            with self.assertRaises(Refusal, msg=name) as caught:
                check_stamp(token, stamped, options)
            self.assertEqual(caught.exception.code, 'stamp-invalid', name)
            self.assertIn(words, caught.exception.message, name)
        # The list of fingerprint methods in the signed data is read for its form only.
        token, stamped, options = stamp_case('Ed25519 with SHA-512, parameters on the list of fingerprint methods only')
        self.assertEqual(check_stamp(token, stamped, options)['state'], 'valid')

    def test_a_time_stamp_signed_with_ed25519_names_sha_512_as_rfc_8419_requires(self):
        token, stamped, options = stamp_case('Ed25519 with SHA-512, as RFC 8419 requires')
        self.assertEqual(check_stamp(token, stamped, options)['state'], 'valid')
        for name in ('Ed25519 with SHA-256 named by the signer', 'Ed25519 with SHA-384 named by the signer'):
            token, stamped, options = stamp_case(name)
            with self.assertRaises(Refusal, msg=name) as caught:
                check_stamp(token, stamped, options)
            self.assertEqual(caught.exception.code, 'stamp-invalid', name)

    def test_a_time_stamp_that_names_the_certificate_that_signed_it_twice_in_the_same_form_is_refused(self):
        for name in ('attributes: the newer form twice, both right', 'attributes: the older form twice, both right'):
            token, stamped, options = stamp_case(name)
            with self.assertRaises(Refusal, msg=name) as caught:
                check_stamp(token, stamped, options)
            self.assertEqual(caught.exception.code, 'stamp-invalid', name)
            self.assertIn('more than once', caught.exception.message, name)
        token, stamped, options = stamp_case('attributes: both forms once each, both right')
        self.assertEqual(check_stamp(token, stamped, options)['state'], 'valid')

    def test_a_time_stamps_time_is_read_to_the_millisecond_a_finer_fraction_dropped(self):
        when = 1791201600000  # 2026-10-05T12:00:00Z

        def read(text):
            data = bytes([0x18, len(text)]) + text.encode('ascii')
            return time_of(data, read_element(data, 0))

        self.assertEqual(read('20261005120000Z'), when)
        self.assertEqual(read('20261005120000.5Z'), when + 500)
        self.assertEqual(read('20261005120000.123Z'), when + 123)
        self.assertEqual(read('20261005120000.1239Z'), when + 123)
        self.assertEqual(read('20261005120000.0009Z'), when)


if __name__ == '__main__':
    unittest.main()
