# The check before acting, with a seal in the book (format description,
# section 20). This version cannot check a seal's third signature
# (SLH-DSA-SHA2-256s), so the check goes on where the seal's first two
# signatures were checked here, and says what it did not check. A book of a
# permission and a seal alone shows the rule itself: the seal's first two
# signatures are the only ones of their methods. Python cannot make a seal,
# so the book is the one in the shared test file, made by the JavaScript
# library.

import json
import pathlib
import unittest

from provared import check_before

VECTORS = pathlib.Path(__file__).resolve().parents[2] / 'test-vectors'
SLH = 'SLH-DSA-SHA2-256s'
NOT_CHECKED = [{'code': 'record-not-sound', 'message': 'This device could not check every signature in the record so far.'}]


def shared_case(name):
    cases = json.loads((VECTORS / 'check-before.json').read_text(encoding='utf-8'))['cases']
    return next(c for c in cases if c['name'] == name)


class TheSealRule(unittest.TestCase):
    def test_the_third_signature_is_let_through_only_where_the_first_two_were_both_checked_here(self):
        c = shared_case('a permission and a seal, on a device without Ed25519 either')
        trusted = {'issuerKeys': c['options']['issuerKeys'], 'sealKeys': c['options']['sealKeys']}
        lone = c['text']
        self.assertEqual([json.loads(line).keys() >= {'seal'} for line in lone.splitlines()], [False, True], 'a permission and a seal')
        for without in ([], [SLH]):
            r = check_before(lone, c['proposal'], {**trusted, 'withoutMethods': without})
            self.assertTrue(r['allowed'], without)
            self.assertEqual(r['notChecked'], [SLH])
        for also in ('ML-DSA-87', 'Ed25519'):
            r = check_before(lone, c['proposal'], {**trusted, 'withoutMethods': [SLH, also]})
            self.assertFalse(r['allowed'], f'without {also} as well: refused')
            self.assertEqual(r['problems'], NOT_CHECKED)
            self.assertNotIn('notChecked', r)


if __name__ == '__main__':
    unittest.main()
