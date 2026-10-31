# The address a permission must have been signed at, named by the reader
# (issuer_origins, or "issuerOrigins" as the JavaScript library names it;
# format description, section 4.4). The shared test files slips.json,
# issuer-origins.json and issuer-origin-shows.json hold the answers both
# languages give, words included. Here: the same rules through Python's own
# way of naming the option, the checker that is carried on, the check
# before acting, and the development stand-in for a passkey.

import json
import pathlib
import unittest

from provared import check_before, check_book, check_show, check_slip, is_page_address, make_show, open_checker
from provared.dev import development_slip
from provared.slip import MAX_ISSUER_ORIGINS

ROOT = pathlib.Path(__file__).resolve().parents[2] / 'test-vectors'

# Where the development stand-in for a passkey signs (dev.py), and another address.
HERE = 'http://localhost'
ELSEWHERE = 'https://sign.example.org'
NOTE = f'This slip was signed at {HERE}, an address you named.'


def codes(problems):
    return [p['code'] for p in problems]


def three():
    """A book with a slip and three stubs, written through the stand-in writer."""
    from provared.dev import development_recorder

    made = development_recorder(actions=['provared.message.send'])
    for _ in range(3):
        made.writer.act({'action': 'provared.message.send'}, lambda: None)
    return made, made.writer.book()


class IsPageAddress(unittest.TestCase):
    def test_the_one_form_the_format_allows(self):
        for ok in ('https://sign.example.org', 'https://example.org', 'https://sign.example.org:8443', 'http://localhost', 'http://localhost:8787', 'https://xn--bcher-kva.example'):
            self.assertTrue(is_page_address(ok), ok)
        bad = (
            'https://Sign.example.org', 'https://sign.example.org/', 'https://sign.example.org:443', 'http://sign.example.org', 'http://app.localhost',
            'https://sign.example.org?a', 'sign.example.org', 'https://1.2.3.4', 'https://sign.example.org:0', '', 'HTTPS://sign.example.org',
            'https://u@sign.example.org', 'https://sign.example.org:65536', 'https://-a.example.org', 'https://a..example.org', ' https://sign.example.org',
            42, None, ['https://sign.example.org'], b'https://sign.example.org',
        )
        for value in bad:
            self.assertFalse(is_page_address(value), repr(value))
        self.assertEqual(MAX_ISSUER_ORIGINS, 64)


class IssuerOrigins(unittest.TestCase):
    def test_named_in_pythons_way_as_in_the_javascript_way(self):
        made = development_slip(actions=['provared.message.send'])
        for origins in ([HERE], [ELSEWHERE], [HERE + '/'], 'x'):
            self.assertEqual(
                check_book(made.book, issuer_keys=made.issuer_keys, issuer_origins=origins),
                check_book(made.book, {'issuerKeys': made.issuer_keys, 'issuerOrigins': origins}),
            )

    def test_a_slip_signed_at_an_address_named_passes_with_a_note_and_one_signed_elsewhere_is_refused(self):
        made = development_slip(actions=['provared.message.send'])
        named = check_slip(made.slip, {'issuerOrigins': [HERE]})
        self.assertEqual(named['problems'], [])
        self.assertIn(NOTE, named['notes'])
        other = check_slip(made.slip, {'issuerOrigins': [ELSEWHERE]})
        self.assertEqual(codes(other['problems']), ['issuer-origin-not-expected'])
        self.assertEqual(other['problems'][0]['message'], 'The slip was signed at a page address other than the ones expected.')
        self.assertEqual(other['signature']['state'], 'valid')
        self.assertEqual(check_slip(made.slip, {'issuerOrigins': [ELSEWHERE, HERE]})['problems'], [])
        self.assertEqual(codes(check_slip(made.slip, {'issuerOrigins': []})['problems']), ['issuer-origin-not-expected'])
        silent = check_slip(made.slip)
        self.assertEqual(silent['problems'], [])
        self.assertFalse(any('address' in n for n in silent['notes']))
        # The passkey is compared first.
        self.assertEqual(codes(check_slip(made.slip, {'issuerKeys': ['A' * 43], 'issuerOrigins': [ELSEWHERE]})['problems']), ['issuer-not-expected'])
        both = check_slip(made.slip, {'issuerKeys': made.issuer_keys, 'issuerOrigins': [HERE]})
        self.assertEqual(both['problems'], [])
        self.assertEqual(both['notes'], [NOTE])

    def test_the_addresses_named_must_be_a_list_of_at_most_64_in_the_plain_form(self):
        made, book = three()
        for value in ('HTTPS://sign.example.org', HERE + '/', 'sign.example.org', 42, None):
            r = check_book(book, issuer_origins=[HERE, value])
            self.assertEqual(codes(r['problems']), ['bad-field'], repr(value))
            self.assertTrue(r['problems'][0]['message'].startswith('issuerOrigins: must be a list of at most 64 page addresses'))
            self.assertTrue(r['summary']['problemFound'])
            self.assertEqual(r['entries'], [])
        for value in (HERE, 'not a list', {'0': HERE, 'length': 1}):
            self.assertEqual(codes(check_book(book, issuer_origins=value)['problems']), ['bad-field'], repr(value))
        # A keyword argument of None is not given, in Python's way; None in the dict form is given, and refused.
        self.assertEqual(check_book(book, issuer_origins=None)['problems'], [])
        self.assertEqual(codes(check_book(book, {'issuerOrigins': None})['problems']), ['bad-field'])
        self.assertEqual(codes(check_book(book, issuer_origins=[HERE] * 65)['problems']), ['bad-field'])
        self.assertEqual(check_book(book, issuer_origins=[HERE] * 64)['problems'], [])
        # A tuple is read as a list, as everywhere in the options.
        self.assertEqual(check_book(book, issuer_origins=(HERE,))['problems'], [])
        self.assertEqual(codes(check_slip(made.slip, {'issuerOrigins': 'x'})['problems']), ['bad-field'])

    def test_a_book_a_show_a_carried_checker_and_the_check_before_acting_answer_alike(self):
        made, book = three()
        trusted = {'issuerKeys': made.issuer_keys}
        good = check_book(book, {**trusted, 'issuerOrigins': [HERE]})
        self.assertTrue(good['summary']['intact'])
        self.assertTrue(good['summary']['withinSlips'])
        self.assertEqual(good['entries'][0]['notes'], [NOTE])
        bad = check_book(book, {**trusted, 'issuerOrigins': [ELSEWHERE]})
        self.assertTrue(bad['summary']['problemFound'])
        self.assertEqual(codes(bad['entries'][0]['problems']), ['issuer-origin-not-expected'])
        for e in bad['entries'][1:]:
            self.assertEqual(codes(e['problems']), ['slip-unusable'])
        self.assertFalse(bad['summary']['withinSlips'])
        carried = open_checker('', {**trusted, 'issuerOrigins': [ELSEWHERE]})
        carried.add(book)
        self.assertEqual(carried.result(), bad)
        show = make_show(book, [0, 1])
        shown = check_show(show, {**trusted, 'issuerOrigins': [ELSEWHERE]})
        self.assertEqual(codes(shown['entries'][0]['problems']), ['issuer-origin-not-expected'])
        self.assertTrue(shown['summary']['problemFound'])
        fine = check_show(show, {**trusted, 'issuerOrigins': [HERE]})
        self.assertEqual(fine['problems'], [])
        self.assertEqual(fine['entries'][0]['notes'], [NOTE])
        self.assertEqual(codes(check_show(show, {**trusted, 'issuerOrigins': ['x']})['problems']), ['bad-field'])
        proposal = {'slip': made.slip_fingerprint, 'action': 'provared.message.send'}
        self.assertTrue(check_before(book, proposal, {**trusted, 'issuerOrigins': [HERE]})['allowed'])
        refused = check_before(book, proposal, {**trusted, 'issuerOrigins': [ELSEWHERE]})
        self.assertFalse(refused['allowed'])
        self.assertEqual(codes(refused['problems']), ['record-not-sound'])
        self.assertFalse(check_before(book, proposal, {**trusted, 'issuerOrigins': [HERE + '/']})['allowed'])

    def test_the_shared_cases_name_the_address(self):
        """The slip cases of the shared test files that name an address: both
        languages answer them alike (test_vectors.py holds every case; this
        shows the three that matter here are there)."""
        cases = json.loads((ROOT / 'slips.json').read_text(encoding='utf-8'))['cases']
        names = {c['name'] for c in cases}
        for name in ('a sound slip, with its address named', 'a sound slip, with another address named', 'a sound slip, with an address named that is not in its plain form'):
            self.assertIn(name, names)
        for file in ('issuer-origins.json', 'issuer-origin-shows.json'):
            self.assertTrue((ROOT / file).exists(), file)


if __name__ == '__main__':
    unittest.main()
