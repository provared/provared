# Seals held elsewhere, handed over beside the book (format description,
# section 21.5). The shared test files held-seals.json, held-seal-shows.json
# and held-seals-before.json hold the answers both languages give, words
# included. Here: the same rules through Python's own way of naming the
# options, the checker that is carried on, and the stub writer.

import json
import pathlib
import unittest
from unittest import mock

from provared import Refusal, check_before, check_book, check_show, generate_key_set, open_checker, open_recorder, write_terms
from provared import book as book_module
from provared.book import MAX_HELD_SEALS
from provared.dev import development_recorder

ROOT = pathlib.Path(__file__).resolve().parents[2] / 'test-vectors'
SLH = 'SLH-DSA-SHA2-256s'


def shared(name):
    cases = json.loads((ROOT / 'held-seals.json').read_text(encoding='utf-8'))['cases']
    return next(c for c in cases if c['name'] == name)


SOUND = shared('a seal held elsewhere that the book holds at its place')
CUT = shared('the book cut back to the first seal, the second held elsewhere')
HELD = SOUND['options']['seals'][0]


def named(options):
    """The options of a shared case, in Python's way of naming them."""
    return {
        'issuer_keys': options['issuerKeys'],
        'seal_keys': options['sealKeys'],
        'stamp_services': options['stampServices'],
        'without_methods': options['withoutMethods'],
    }


def codes(result):
    return [p['code'] for p in result['problems']]


class HeldSeals(unittest.TestCase):
    def test_named_in_pythons_way_as_in_the_javascript_way(self):
        for case in (SOUND, CUT):
            self.assertEqual(check_book(case['text'], seals=case['options']['seals'], **named(case['options'])), check_book(case['text'], case['options']))

    def test_the_book_holds_it_and_nothing_else_changes(self):
        without = {k: v for k, v in SOUND['options'].items() if k != 'seals'}
        r = check_book(SOUND['text'], SOUND['options'])
        plain = check_book(SOUND['text'], without)
        self.assertEqual(r['problems'], [])
        self.assertEqual(r['entries'], plain['entries'])
        self.assertEqual(r['summary'], plain['summary'])
        h = r['held'][0]
        self.assertEqual((h['kind'], h['used'], h['place'], h['inBook']), ('seal', True, 5, 5))
        self.assertIn(f'This device could not check its third signature ({SLH}). It was used on the strength of its Ed25519 and ML-DSA-87 signatures, which were checked here.', h['notes'])

    def test_cut_short_and_not_in_book(self):
        self.assertEqual(codes(check_book(CUT['text'], CUT['options'])), ['book-cut-short'])
        swapped = shared('another seal of the same entries in the place of the one held elsewhere')
        self.assertEqual(codes(check_book(swapped['text'], swapped['options'])), ['seal-not-in-book'])

    def test_limits_of_what_is_handed_over(self):
        self.assertEqual(MAX_HELD_SEALS, 64)
        r = check_book(SOUND['text'], {**SOUND['options'], 'seals': [5] * 65})
        self.assertEqual(r['problems'][0]['message'], 'seals: must be a list of 0 to 64 items.')
        without = {k: v for k, v in SOUND['options'].items() if k != 'seals'}
        self.assertEqual(check_book(SOUND['text'], {**without, 'seals': []}), check_book(SOUND['text'], without))
        # A tuple is a list, as JSON would hold it.
        self.assertEqual(check_book(SOUND['text'], {**SOUND['options'], 'seals': (HELD,)}), check_book(SOUND['text'], SOUND['options']))

    def test_a_checker_carried_on_gives_the_whole_checks_answer_after_every_line(self):
        lines = SOUND['text'].split('\n')[:-1]
        carried = open_checker('', SOUND['options'])
        for i, line in enumerate(lines):
            carried.add(line + '\n')
            self.assertEqual(carried.result(), check_book('\n'.join(lines[: i + 1]) + '\n', SOUND['options']), f'after line {i}')

    def test_a_checker_carried_on_checks_the_seals_handed_over_once(self):
        two = shared('two seals held elsewhere, handed over out of their order')
        carried = open_checker(two['text'], two['options'])
        once = carried.result()
        calls = []
        real = book_module.verify_signature

        def counting(*args, **kwargs):
            calls.append(1)
            return real(*args, **kwargs)

        with mock.patch.object(book_module, 'verify_signature', counting):
            self.assertEqual(carried.result(), once)
        self.assertEqual(calls, [])
        # A whole check of the same book checks them, as a check that starts afresh must.
        with mock.patch.object(book_module, 'verify_signature', counting):
            check_book(two['text'], two['options'])
        self.assertGreater(len(calls), 0)

    def test_the_check_before_acting_excuses_only_a_held_seal_whose_first_two_signatures_it_checked(self):
        cases = json.loads((ROOT / 'held-seals-before.json').read_text(encoding='utf-8'))['cases']
        alone, without_ed, without_ml = cases[2:]
        self.assertEqual(check_before(alone['text'], alone['proposal'], alone['options'])['notChecked'], [SLH])
        for case in (without_ed, without_ml):
            answer = check_before(case['text'], case['proposal'], case['options'])
            self.assertFalse(answer['allowed'])
            self.assertEqual(codes(answer), ['record-not-sound'])

    def test_a_show_does_not_use_them(self):
        cases = json.loads((ROOT / 'held-seal-shows.json').read_text(encoding='utf-8'))['cases']
        r = check_show(cases[0]['show'], cases[0]['options'])
        self.assertEqual(r['held'], [])
        self.assertTrue(any(n.startswith('Seals held elsewhere were handed over beside this Show. They were not used') for n in r['notes']))

    def test_the_check_before_acting_allows_nothing_on_a_book_cut_short(self):
        cases = json.loads((ROOT / 'held-seals-before.json').read_text(encoding='utf-8'))['cases']
        sound, cut = cases[:2]
        self.assertTrue(check_before(sound['text'], sound['proposal'], sound['options'])['allowed'])
        self.assertEqual(check_before(sound['text'], sound['proposal'], sound['options'])['notChecked'], [SLH])
        answer = check_before(cut['text'], cut['proposal'], cut['options'])
        self.assertFalse(answer['allowed'])
        self.assertEqual(codes(answer), ['record-not-sound'])

    def test_a_seal_this_device_cannot_check_in_full_leaves_the_record_not_fully_checked(self):
        first = shared('two seals held elsewhere, handed over out of their order')['options']['seals'][1]
        lines = SOUND['text'].split('\n')[:3]
        options = {k: v for k, v in SOUND['options'].items() if k not in ('seals', 'sealKeys')}
        r = check_book('\n'.join(lines) + '\n', {**options, 'seals': [first]})
        self.assertEqual(r['problems'], [])
        self.assertFalse(r['held'][0]['used'])
        self.assertFalse(r['summary']['fullyChecked'])
        self.assertEqual(r['summary']['methodsMissing'], [SLH])

    def test_the_stub_writer_takes_them_with_its_options(self):
        # A seal of another book: its recorder is not named, so it is not used, and the writer acts.
        made = development_recorder({'actions': ['supplies.order']}, {'options': {'seals': [HELD]}})
        taken = made.writer.act({'action': 'supplies.order'}, lambda: 'ok')
        self.assertTrue(taken['done'])
        held = made.writer.check()['held']
        self.assertEqual([(h['kind'], h['used']) for h in held], [('seal', False)])
        self.assertEqual(made.writer.cancellations(), [])
        # Its recorder named: the seal stands at entry 5 of a book of one entry, which was cut short.
        with self.assertRaises(Refusal) as refused:
            development_recorder({'actions': ['supplies.order']}, {'options': {'seals': [HELD], 'sealKeys': SOUND['options']['sealKeys']}})
        self.assertIn('A problem was found in the record so far', str(refused.exception))
        # A sound book that holds the seal: the writer opens on it, and takes the seal it was handed for a seal, not for a
        # cancellation. (Its keys are not the agent's; it is not asked to act.)
        slip = check_book(SOUND['text'], SOUND['options'])['entries'][0]['fingerprint']
        _, others = generate_key_set()
        options = {k: v for k, v in SOUND['options'].items() if k != 'issuerKeys'}
        writer = open_recorder(SOUND['text'], slip, others, SOUND['options']['issuerKeys'], options=options)
        self.assertEqual([(h['kind'], h['used'], h['inBook']) for h in writer.check()['held']], [('seal', True, 5)])
        self.assertEqual(writer.cancellations(), [])
        # Another party's entry joins the book: the writer reads it on a copy of what it keeps, and the seal is still found.
        service, service_private = generate_key_set()
        terms = write_terms({'by': {'keys': service, 'name': 'A service (invented)'}, 'accepts': ['supplies.order'], 'validFrom': '2026-10-05T00:00:00Z', 'validUntil': '2026-10-12T00:00:00Z'}, service_private)
        writer.add({'terms': terms['record']})
        self.assertEqual([(h['kind'], h['used'], h['inBook']) for h in writer.check()['held']], [('seal', True, 5)])
        self.assertEqual(writer.check()['problems'], [])


if __name__ == '__main__':
    unittest.main()
