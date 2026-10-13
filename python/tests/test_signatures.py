# The length of a signature. An Ed25519 signature is 64 bytes, an ML-DSA-87
# signature 4,627 and an SLH-DSA-SHA2-256s signature 29,792 (RFC 8032,
# FIPS 204, FIPS 205). One shorter or longer can never check, so no device
# calls it "not checked here", whether or not it has the method (format
# description, section 3.9). The shared test files hold a seal whose third
# signature is cut short; these tests hold the rule for every method, both
# ways, with and without the method.

import json
import unittest

from test_recorder import World, order

from provared import check_book, to_base64url, write_book
from provared.signatures import generate_key_set, verify_signature

SLH_KEY = {'alg': 'SLH-DSA-SHA2-256s', 'kty': 'AKP', 'pub': to_base64url(bytes(64))}


class SignatureLengths(unittest.TestCase):
    def test_a_signature_of_another_length_than_its_methods_is_invalid_with_the_method_or_without_it(self):
        keys, _ = generate_key_set()
        for key, length in ((keys[0], 64), (keys[1], 4627), (SLH_KEY, 29792)):
            for wrong in (0, length - 1, length + 1, 2 * length):
                for without in ((), (key['alg'],)):
                    where = f"{key['alg']}, {wrong} bytes, {'without' if without else 'with'} the method"
                    self.assertEqual(verify_signature(key, bytes(wrong), b'x', without), 'invalid', where)
            # Of the right length, on a device without the method: not checked here, never a pass.
            self.assertEqual(verify_signature(key, bytes(length), b'x', (key['alg'],)), 'unavailable', key['alg'])

    def test_a_book_whose_signatures_are_emptied_has_a_problem_on_a_device_with_neither_method(self):
        w = World()
        writer = w.open()
        self.assertTrue(writer.act(order(1), lambda: None)['done'])
        entries = [{'slip': w.slip}]
        for line in writer.book().splitlines()[1:]:
            entry = json.loads(line)
            entry['stub'] = {**entry['stub'], 'signatures': [{**s, 'signature': ''} for s in entry['stub']['signatures']]}
            entries.append(entry)
        result = check_book(write_book(entries), {'issuerKeys': w.issuer_keys, 'withoutMethods': ['Ed25519', 'ML-DSA-87']})
        self.assertTrue(result['summary']['problemFound'])
        self.assertFalse(result['summary']['intact'])
        self.assertEqual([s['state'] for s in result['entries'][1]['signatures']], ['invalid', 'invalid'])


if __name__ == '__main__':
    unittest.main()
