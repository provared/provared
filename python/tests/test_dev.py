# The development stand-in for a passkey (provared.dev): a record made with
# it checks exactly as one signed by a person would, and every slip it
# signs says in its issuer's name that it is for development.

import os
import subprocess
import sys
import tempfile
import unittest

from provared import check_book, check_slip, thumbprint
from provared.dev import DEVELOPMENT_MARK, development_passkey, development_recorder, development_slip

SEND = 'provared.message.send'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class DevelopmentStandIn(unittest.TestCase):

    def test_a_development_slip_checks_and_its_issuer_is_marked(self):
        made = development_slip({'actions': [SEND], 'limits': [{'action': SEND, 'count': 2}]})
        checked = check_slip(made.slip, {'issuerKeys': made.issuer_keys})
        self.assertEqual(checked['problems'], [])
        self.assertEqual(checked['content']['issuer']['name'], f'Development passkey {DEVELOPMENT_MARK}')
        self.assertEqual(checked['content']['issuer']['origin'], 'http://localhost')
        self.assertEqual(checked['content']['agent']['name'], 'Development agent')
        self.assertEqual(checked['content']['actions'], [SEND])
        self.assertEqual(checked['content']['with'], [])
        self.assertIn('development', checked['content']['purpose'])
        self.assertEqual(made.issuer_keys, [thumbprint(made.passkey.key)])
        book = check_book(made.book, issuer_keys=made.issuer_keys)
        self.assertTrue(book['summary']['intact'])
        self.assertEqual(book['summary']['counts']['slips'], 1)

    def test_a_given_name_keeps_the_mark_and_the_keys_cannot_be_replaced(self):
        named = development_slip(actions=[SEND], issuer={'name': 'Sam'}, agent={'name': 'Mailer'}, purpose='Send three messages.')
        content = check_slip(named.slip, {'issuerKeys': named.issuer_keys})['content']
        self.assertEqual(content['issuer']['name'], 'Sam (development)')
        self.assertEqual(content['agent']['name'], 'Mailer')
        self.assertEqual(content['purpose'], 'Send three messages.')
        twice = development_slip({'actions': [SEND], 'issuer': {'name': 'Sam (development)'}})
        self.assertEqual(check_slip(twice.slip, {'issuerKeys': twice.issuer_keys})['content']['issuer']['name'], 'Sam (development)')
        forced = development_slip({'actions': [SEND], 'issuer': {'name': 'Sam', 'origin': 'https://sign.example.org', 'rpId': 'sign.example.org'}})
        self.assertEqual(check_slip(forced.slip, {'issuerKeys': forced.issuer_keys})['content']['issuer']['origin'], 'http://localhost')

    def test_the_stand_in_refuses_what_prepare_slip_refuses(self):
        with self.assertRaises(Exception):
            development_slip()
        with self.assertRaises(TypeError):
            development_slip('send')
        with self.assertRaisesRegex(Exception, r'limits\[0\]\.action'):
            development_slip({'actions': [SEND], 'limits': [{'action': 'other', 'count': 1}]})

    def test_the_stand_in_signs_as_a_passkey_would(self):
        passkey = development_passkey()
        first = passkey.sign(bytes(32))
        second = passkey.sign(bytes(32))
        self.assertEqual(len(first[0]), 37)
        self.assertEqual(first[0][32], 0x05)
        self.assertNotEqual(first[2], second[2])
        self.assertIn(b'"origin":"http://localhost"', first[1])

    def test_the_writer_under_a_development_slip(self):
        made = development_recorder({'actions': [SEND], 'limits': [{'action': SEND, 'count': 2}]})
        sent = []
        for i in range(1, 4):
            outcome = made.writer.act({'action': SEND}, lambda i=i: sent.append(i))
            self.assertEqual(outcome['done'], i <= 2, f'message {i}')
            if i == 3:
                self.assertEqual(outcome['answer']['breaches'][0]['code'], 'over-count-limit')
        self.assertEqual(sent, [1, 2])
        result = check_book(made.writer.book(), issuer_keys=made.issuer_keys)
        self.assertTrue(result['summary']['intact'])
        self.assertTrue(result['summary']['withinSlips'])
        self.assertEqual(result['summary']['counts']['stubs'], 2)
        self.assertEqual(result['entries'][0]['fingerprint'], made.slip_fingerprint)
        self.assertEqual(result['entries'][0]['content']['issuer']['name'], 'Development passkey (development)')

    def test_the_first_record_example_runs_and_its_book_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            env = {**os.environ, 'PYTHONPATH': os.path.join(ROOT, 'src')}
            run = subprocess.run([sys.executable, os.path.join(ROOT, 'examples', 'first_record.py')],
                                 cwd=folder, env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('message 1 sent', run.stdout)
            self.assertIn('message 3 not sent: [over-count-limit]', run.stdout)
            with open(os.path.join(folder, 'book.jsonl'), encoding='utf-8') as f:
                book = f.read()
            self.assertEqual(len([line for line in book.split('\n') if line]), 3)
            thumb = run.stdout.split('--issuer ')[1].split()[0]
            result = check_book(book, issuer_keys=[thumb])
            self.assertTrue(result['summary']['intact'])
            self.assertTrue(result['summary']['withinSlips'])


if __name__ == '__main__':
    unittest.main()
