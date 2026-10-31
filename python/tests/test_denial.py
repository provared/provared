# The denial: the agent's own side states that it did not take an action
# that was asked for, and why (format description, section 28). The shared
# test files (denial-*.json, denials-written.json) hold the answers both
# languages give, words included. Here: what only the Python version has to
# show, and the rules that matter most, once more in Python's own words.

import base64
import json
import pathlib
import re
import unittest

from provared import FINDING_CODES, NotTaken, Refusal, check_book, denial_codes, record_tools, write_denial
from provared.dev import development_recorder

ORDER = 'supplies.order'
ROOT = pathlib.Path(__file__).resolve().parents[2]


def order(value):
    return {'action': ORDER, 'amount': {'unit': 'GBP', 'value': value}}


def content_of(line):
    payload = json.loads(line)['denial']['payload']
    return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))


def opened(**more):
    return development_recorder({'actions': [ORDER], 'limits': [{'action': ORDER, 'max': 100, 'unit': 'GBP'}]}, more)


class Denials(unittest.TestCase):
    def test_written_when_act_refuses_and_never_with_a_stub(self):
        made = opened(denials=True)
        w = made.writer
        self.assertIs(w.denials, True)
        refused = w.act(order(250), lambda: self.fail('not taken'))
        self.assertFalse(refused['done'])
        self.assertTrue(refused['denial']['written'])
        self.assertEqual(content_of(refused['denial']['line'])['codes'], ['over-limit'])
        taken = w.act(order(10), lambda: 'ok')
        self.assertTrue(taken['done'])
        self.assertNotIn('denial', taken)
        quiet = w.act(order(300), lambda: 'x', {'denial': False})
        self.assertNotIn('denial', quiet)
        r = check_book(w.book(), issuer_keys=made.issuer_keys)
        self.assertEqual([e['kind'] for e in r['entries']], ['slip', 'denial', 'stub'])
        self.assertTrue(r['summary']['intact'])
        self.assertTrue(r['summary']['withinSlips'])
        self.assertEqual(r['summary']['counts']['denials'], 1)

    def test_none_without_denials(self):
        w = opened().writer
        self.assertIs(w.denials, False)
        self.assertNotIn('denial', w.act(order(250), lambda: 'x'))
        self.assertFalse(w.deny(order(1), {'source': 'person'})['written'])
        with self.assertRaises(AttributeError):
            w.denials = True

    def test_the_hourly_limit_stops_denials_never_a_stub(self):
        w = opened(denials=True, denials_per_hour=1).writer
        self.assertTrue(w.act({'action': 'provared.data.delete'}, lambda: None)['denial']['written'])
        over = w.deny(order(1), {'source': 'rule'})
        self.assertEqual((over['written'], over['problem']['code'], over['notWritten']), (False, 'denials-over-limit', 1))
        self.assertTrue(w.act(order(5), lambda: 'ok')['done'])

    def test_the_hourly_limit_counts_at_the_writers_clock(self):
        clock = [1_800_000_000_000]
        w = opened(denials=True, denials_per_hour=10, now=lambda: clock[0]).writer

        def back():
            return w.deny(order(1), {'source': 'rule', 'when': clock[0] - 299_000})

        written = sum(1 for _ in range(10) if back()['written'])
        clock[0] += 3_302_000
        written += sum(1 for _ in range(10) if back()['written'])
        self.assertEqual(written, 10)
        clock[0] += 299_000
        self.assertTrue(back()['written'])

    def test_an_own_denial_through_add_counts_at_the_clock(self):
        clock = [1_800_000_000_000]
        made = opened(denials=True, denials_per_hour=2, now=lambda: clock[0])
        w = made.writer
        old = write_denial({'slip': made.slip_fingerprint, 'action': ORDER, 'source': 'rule', 'when': clock[0] - 7_200_000}, made.agent_private_keys)
        w.add({'denial': old['record']})
        self.assertTrue(w.deny(order(1), {'source': 'rule'})['written'])
        over = w.deny(order(1), {'source': 'rule'})
        self.assertEqual((over['written'], over['problem']['code']), (False, 'denials-over-limit'))

    def test_deny_from_inside_an_action_is_refused(self):
        w = opened(denials=True).writer
        seen = []

        def perform():
            try:
                w.deny(order(2), {'source': 'rule'})
                seen.append('written')
            except Exception as e:
                seen.append(str(e))

        w.act(order(1), perform)
        self.assertRegex(seen[0], 'from inside an action it is taking')

    def test_tools_leave_a_denial_by_the_person_and_no_arguments_in_clear(self):
        made = development_recorder(
            {'actions': [ORDER], 'requires': [{'need': 'approval', 'action': ORDER}]},
            {'denials': True},
        )
        tools = record_tools(made.writer, {'buy': {'action': ORDER, 'run': lambda a: 'bought', 'approve': lambda request, a: None}})
        with self.assertRaises(NotTaken) as caught:
            tools['buy']({'item': 'a secret item name'})
        self.assertTrue(caught.exception.denial['written'])
        self.assertEqual(content_of(caught.exception.denial['line'])['source'], 'person')
        self.assertNotIn('secret', made.writer.book())
        self.assertNotIn('secret', json.dumps(content_of(caught.exception.denial['line'])))

    def test_write_denial_and_its_rules(self):
        made = opened()
        fields = {'slip': made.slip_fingerprint, 'action': ORDER, 'source': 'check', 'codes': ['over-limit']}
        self.assertEqual(write_denial(fields, made.agent_private_keys)['record']['signatures'][0]['protected'][:10], 'eyJ0eXAiOi')
        with self.assertRaises(Refusal):
            write_denial({**fields, 'codes': ['details-not-added']}, made.agent_private_keys)
        with self.assertRaises(Refusal):
            write_denial({**fields, 'source': 'person'}, made.agent_private_keys)

    def test_the_list_of_codes_is_the_table_of_the_list_of_threats(self):
        text = (ROOT / 'docs' / 'threat-model.md').read_text(encoding='utf-8').split('## 8.')[1].split('## 9.')[0]
        listed = re.findall(r'^\| `([a-z0-9-]+)` \|', text, re.M)
        self.assertEqual(sorted(listed), sorted(FINDING_CODES))
        self.assertEqual(denial_codes({'problems': [{'code': 'details-not-added'}], 'breaches': []}), ['check-failed'])


if __name__ == '__main__':
    unittest.main()
