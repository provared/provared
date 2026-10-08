# Records written by this library: the approval, the refusal, a service's
# terms, the cancellation, the acknowledgement, the vouching record, the
# withdrawal and the pass. Each is written, read back as a record of its
# kind, its content confirmed and every signature checked.
#
# The shared test files (test_vectors.py) show that these writers give the
# same content, fingerprint and Ed25519 signature as the JavaScript library.

import json
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from provared import approval, fields, pass_, service, standing
from provared.encoding import Refusal, now_ms, parse_time, sha256, to_base64url, utf8
from provared.jws import parse_record, signing_input
from provared.signatures import generate_key_set, verify_signature
from provared.slip import check_passkey_signature

RP_ID = 'localhost'
ORIGIN = 'http://localhost:8787'
FP = to_base64url(bytes([1]) * 32)
FP2 = to_base64url(bytes([3]) * 32)
FROM = '2026-10-05T08:00:00Z'
UNTIL = '2026-10-12T08:00:00Z'
T = 1791190800000  # 2026-10-05T09:00:00Z


class Passkey:
    """A software stand-in for a passkey (ES256): the same three values a real
    passkey returns, in the forms the Web Authentication standard sets out."""

    def __init__(self):
        self._private = ec.generate_private_key(ec.SECP256R1())
        numbers = self._private.public_key().public_numbers()
        self.key = {'alg': 'ES256', 'crv': 'P-256', 'kty': 'EC', 'x': to_base64url(numbers.x.to_bytes(32, 'big')), 'y': to_base64url(numbers.y.to_bytes(32, 'big'))}
        self.issuer = {'key': self.key, 'rpId': RP_ID, 'origin': ORIGIN}

    def sign(self, challenge):
        client_data_json = utf8(json.dumps({'type': 'webauthn.get', 'challenge': to_base64url(challenge), 'origin': ORIGIN, 'crossOrigin': False}, separators=(',', ':')))
        # Flags 0x05: user present and user verified.
        authenticator_data = sha256(utf8(RP_ID)) + bytes([0x05, 0, 0, 0, 1])
        signature = self._private.sign(authenticator_data + sha256(client_data_json), ec.ECDSA(hashes.SHA256()))
        return authenticator_data, client_data_json, signature


class WrittenRecords(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys, cls.private_keys = generate_key_set()
        cls.helper_keys, _ = generate_key_set()

    def signed(self, kind, out):
        """Read a record written with the class's key set, and check it."""
        self.assertEqual(sorted(out), ['fingerprint', 'record'])
        parsed = parse_record(out['record'], kind)
        self.assertEqual(parsed.fingerprint, out['fingerprint'])
        self.assertEqual(len(parsed.signatures), 2)
        for key, s in zip(self.keys, parsed.signatures):
            self.assertEqual(verify_signature(key, s['signature'], signing_input(s['protected_b64'], parsed.payload_b64)), 'valid')
        return parsed.content

    def by(self):
        return {'name': 'Example Stationery (invented)', 'keys': self.keys}

    def test_refusal(self):
        out = service.write_refusal({'slip': FP, 'by': self.by(), 'action': 'supplies.order', 'reason': 'over-limit', 'amount': {'unit': 'GBP', 'value': 250}, 'when': T}, self.private_keys)
        content = self.signed('refusal', out)
        service.validate_refusal_content(content)
        self.assertEqual(content['type'], 'provared.refusal.v0')
        self.assertEqual(content['reason'], 'over-limit')
        self.assertEqual(content['amount'], {'unit': 'GBP', 'value': 250})
        self.assertEqual(content['when'], '2026-10-05T09:00:00Z')

    def test_terms(self):
        out = service.write_terms({'by': self.by(), 'accepts': ['supplies.order', 'provared.order.place'], 'validFrom': FROM, 'validUntil': UNTIL}, self.private_keys)
        content = self.signed('terms', out)
        service.validate_terms_content(content)
        self.assertEqual(content['never'], [])
        self.assertNotIn('when', content)

    def test_acknowledgement(self):
        for extra in ({}, {'pass': FP2}):
            out = standing.write_acknowledgement({'slip': FP, 'cancellation': FP2, 'when': T, **extra}, self.private_keys)
            content = self.signed('acknowledgement', out)
            standing.validate_acknowledgement_content(content)
            self.assertEqual('pass' in content, bool(extra))

    def test_vouching(self):
        recorder_keys = [*self.helper_keys, {'alg': 'SLH-DSA-SHA2-256s', 'kty': 'AKP', 'pub': to_base64url(bytes(64))}]
        who = [
            {'kind': 'person', 'name': 'Sam Example', 'key': Passkey().key},
            {'kind': 'agent', 'name': 'Office supplies agent', 'keys': self.helper_keys},
            {'kind': 'service', 'name': 'Example Stationery (invented)', 'keys': self.helper_keys},
            {'kind': 'recorder', 'name': 'Example recorder (invented)', 'keys': recorder_keys},
        ]
        for w in who:
            out = standing.write_vouching({'by': {'name': 'Example Ltd (invented)', 'keys': self.keys}, 'for': w, 'validFrom': FROM, 'validUntil': UNTIL, 'when': T}, self.private_keys)
            content = self.signed('vouching', out)
            standing.validate_vouching_content(content)
            self.assertEqual(content['for'], w)
            self.assertIn(w['kind'], standing.VOUCHED_KINDS)

    def test_withdrawal(self):
        out = standing.write_withdrawal({'vouching': FP, 'when': T}, self.private_keys)
        content = self.signed('withdrawal', out)
        standing.validate_withdrawal_content(content)

    def test_pass(self):
        given = {'slip': FP, 'to': {'name': 'Helper agent', 'keys': self.helper_keys}, 'actions': ['supplies.order'], 'validFrom': FROM, 'validUntil': UNTIL, 'when': T}
        content = self.signed('pass', pass_.write_pass(given, self.private_keys))
        pass_.validate_pass_content(content)
        self.assertEqual(content['limits'], [])
        self.assertNotIn('from', content)
        limits = [{'action': 'supplies.order', 'max': 100, 'unit': 'GBP', 'per': 86400}]
        content = self.signed('pass', pass_.write_pass({**given, 'from': FP2, 'limits': limits}, self.private_keys))
        self.assertEqual(content['from'], FP2)
        self.assertEqual(content['limits'], limits)
        self.assertEqual(pass_.MAX_PASSES, 10)

    def test_defaults(self):
        # Without "id" and "when", a new unique number and the time now.
        before = now_ms() // 1000 * 1000
        content = self.signed('withdrawal', standing.write_withdrawal({'vouching': FP}, self.private_keys))
        after = now_ms()
        fields.id_(content['id'], 'id')
        self.assertTrue(before <= parse_time(content['when']) <= after)
        other = self.signed('withdrawal', standing.write_withdrawal({'vouching': FP}, self.private_keys))
        self.assertNotEqual(content['id'], other['id'])

    def test_refused(self):
        writers = [
            lambda: service.write_refusal({'slip': FP, 'by': self.by(), 'action': 'supplies.order', 'reason': 'because'}, self.private_keys),
            lambda: service.write_terms({'by': self.by(), 'accepts': ['provared.order.place'], 'never': ['commits'], 'validFrom': FROM, 'validUntil': UNTIL}, self.private_keys),
            lambda: standing.write_acknowledgement({'slip': FP, 'cancellation': 'x'}, self.private_keys),
            lambda: standing.write_vouching({'by': self.by(), 'for': {'kind': 'organisation', 'name': 'x'}, 'validFrom': FROM, 'validUntil': UNTIL}, self.private_keys),
            lambda: standing.write_withdrawal({'vouching': FP2[:-1]}, self.private_keys),
            lambda: pass_.write_pass({'slip': FP, 'to': {'name': 'Helper', 'keys': self.helper_keys}, 'actions': [], 'validFrom': FROM, 'validUntil': UNTIL}, self.private_keys),
        ]
        for write in writers:
            with self.assertRaises(Refusal) as caught:
                write()
            self.assertEqual(caught.exception.code, 'bad-field')

    def test_approval(self):
        passkey = Passkey()
        given = {'slip': FP, 'action': 'supplies.order', 'amount': {'unit': 'GBP', 'value': 150}, 'with': 'supplier', 'details': [{'name': 'order.pdf', 'sha256': FP2}], 'when': T}
        prepared = approval.prepare_approval(given)
        self.assertEqual(prepared['challenge'], sha256(signing_input(prepared['protectedB64'], prepared['payloadB64'])))
        record = approval.assemble_approval(prepared, *passkey.sign(prepared['challenge']))
        parsed = parse_record(record, 'approval')
        self.assertEqual(parsed.fingerprint, prepared['fingerprint'])
        self.assertEqual(parsed.content_bytes, prepared['contentBytes'])
        approval.validate_approval_content(parsed.content)
        self.assertEqual(check_passkey_signature(parsed, passkey.issuer), 'valid')
        # Another passkey did not sign it.
        with self.assertRaises(Refusal) as caught:
            check_passkey_signature(parsed, Passkey().issuer)
        self.assertEqual(caught.exception.code, 'signature-invalid')
        # What the approval and the agent's stub must agree on.
        stub = {'type': 'provared.stub.v0', 'seq': 0, 'action': 'supplies.order', 'with': 'supplier', 'amount': {'value': 150, 'unit': 'GBP'}, 'details': given['details'], 'approval': prepared['fingerprint']}
        self.assertEqual(approval.request_of(parsed.content), approval.request_of(stub))
        self.assertNotEqual(approval.request_of(parsed.content), approval.request_of({**stub, 'amount': {'unit': 'GBP', 'value': 151}}))

    def test_cancellation(self):
        passkey = Passkey()
        prepared = standing.prepare_cancellation({'slip': FP, 'when': T})
        record = standing.assemble_cancellation(prepared, *passkey.sign(prepared['challenge']))
        parsed = parse_record(record, 'cancellation')
        self.assertEqual(parsed.fingerprint, prepared['fingerprint'])
        standing.validate_cancellation_content(parsed.content)
        self.assertEqual(parsed.content['slip'], FP)
        self.assertEqual(check_passkey_signature(parsed, passkey.issuer), 'valid')


if __name__ == '__main__':
    unittest.main()
