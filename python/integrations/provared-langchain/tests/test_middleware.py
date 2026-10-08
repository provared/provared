# ProvaredMiddleware: every tool call of a LangChain agent, recorded. The
# agent runs with LangChain's own stand-in model, scripted in advance, inside
# the examples' guard that refuses any connection outside this program.
#
# Run from this package's folder, with the examples' environment:
#   ../../.venv-examples/Scripts/python -m unittest discover -s tests

import asyncio
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..', '..', 'examples'))

os.environ['LANGSMITH_TRACING'] = 'false'
os.environ['LANGCHAIN_TRACING_V2'] = 'false'

from langchain.agents import create_agent  # noqa: E402
from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langsmith import tracing_context  # noqa: E402
from provared import Refusal, arguments_fingerprint, check_book  # noqa: E402

from provared_langchain import ProvaredMiddleware  # noqa: E402

from _world import MESSAGE, ORDER, SUPPLIER, World, offline, order_amount, refused  # noqa: E402
from langchain_example import ScriptedChatModel, call, make_tools  # noqa: E402

TOOLS = {'order_supplies': {'action': ORDER, 'with': SUPPLIER, 'amount': order_amount}, 'send_message': MESSAGE}
PAPER = {'item': 'printer paper', 'quantity': 5, 'total_gbp': 30}
DESK = {'item': 'standing desk', 'quantity': 1, 'total_gbp': 250}
NOTE = {'to': 'Sam', 'text': 'The paper is ordered.'}
DONE = AIMessage(content='Done.')
QUESTION = {'messages': [{'role': 'user', 'content': 'Order paper and a standing desk.'}]}


def stubs(world):
    return [e['content'] for e in check_book(world.writer.book(), issuer_keys=world.issuer_keys)['entries'] if e['kind'] == 'stub']


def answers(state):
    return [m for m in state['messages'] if isinstance(m, ToolMessage)]


class Middleware(unittest.TestCase):
    def run_agent(self, world, script, middleware, tools=None, asynchronous=False):
        agent = create_agent(ScriptedChatModel(messages=iter(script)),
                             tools=list(make_tools(world).values()) if tools is None else tools,
                             middleware=[middleware])
        refused.clear()
        try:
            with offline(), tracing_context(enabled=False):
                return asyncio.run(agent.ainvoke(QUESTION)) if asynchronous else agent.invoke(QUESTION)
        finally:
            self.assertEqual(refused, [])

    def test_a_call_inside_the_slip_runs_and_one_over_it_does_not(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                state = self.run_agent(world, [call('order_supplies', PAPER, 1), call('order_supplies', DESK, 2), DONE],
                                       ProvaredMiddleware(world.writer, TOOLS), asynchronous=asynchronous)
                self.assertEqual(world.orders, [PAPER])
                told = answers(state)
                self.assertEqual([m.status for m in told], ['success', 'error'])
                self.assertEqual(told[0].content, 'Ordered 5 x printer paper for 30 GBP.')
                self.assertTrue(told[1].content.startswith(
                    'The tool "order_supplies" was not run. With this action the total would be 280 GBP.'))
                [stub] = stubs(world)
                self.assertEqual((stub['action'], stub['with'], stub['amount']), (ORDER, SUPPLIER, {'unit': 'GBP', 'value': 30}))
                self.assertEqual(stub['details'], [{'name': 'arguments', 'sha256': arguments_fingerprint(PAPER)}])
                summary = check_book(world.writer.book(), issuer_keys=world.issuer_keys)['summary']
                self.assertTrue(summary['intact'] and summary['withinSlips'])

    def test_a_tool_that_is_not_described_is_refused_or_run_unrecorded(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                state = self.run_agent(world, [call('send_message', NOTE, 1), DONE],
                                       ProvaredMiddleware(world.writer, {'order_supplies': TOOLS['order_supplies']}),
                                       asynchronous=asynchronous)
                self.assertEqual(world.messages, [])
                self.assertEqual(answers(state)[0].content, 'The tool "send_message" was not run. Provared records no tool of that name.')
                world = World()
                self.run_agent(world, [call('send_message', NOTE, 1), DONE],
                               ProvaredMiddleware(world.writer, {'order_supplies': TOOLS['order_supplies']}, unlisted='run'),
                               asynchronous=asynchronous)
                self.assertEqual((world.messages, stubs(world)), ([NOTE], []))

    def test_a_tool_that_answers_with_an_error_leaves_no_stub(self):
        # LangChain checks the arguments against the tool's schema after the
        # middleware, and answers the model with an error where they do not fit.
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                state = self.run_agent(world, [call('order_supplies', {**PAPER, 'quantity': 'many'}, 1), DONE],
                                       ProvaredMiddleware(world.writer, TOOLS), asynchronous=asynchronous)
                self.assertEqual([m.status for m in answers(state)], ['error'])
                self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_tool_that_fails_leaves_no_stub_and_its_error_is_passed_on(self):
        def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            raise ValueError('the supplier is closed')

        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                with self.assertRaises(ValueError):
                    self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredMiddleware(world.writer, TOOLS),
                                   tools=[order_supplies], asynchronous=asynchronous)
                self.assertEqual(stubs(world), [])

    def test_a_tool_that_calls_the_writer_is_refused_at_once(self):
        # Also where the tool runs on the event loop and the writer in a thread of its own.
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()

                def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
                    """Order office supplies."""
                    world.writer.act({'action': MESSAGE}, lambda: None)
                    return 'ordered'

                with self.assertRaises(RuntimeError) as raised:
                    self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredMiddleware(world.writer, TOOLS),
                                   tools=[order_supplies], asynchronous=asynchronous)
                self.assertIn('from inside an action', str(raised.exception))
                self.assertEqual(stubs(world), [])

    def test_two_calls_in_one_reply_are_both_recorded(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                both = AIMessage(content='', tool_calls=[{'name': 'order_supplies', 'args': PAPER, 'id': 'call-1', 'type': 'tool_call'},
                                                         {'name': 'send_message', 'args': NOTE, 'id': 'call-2', 'type': 'tool_call'}])
                self.run_agent(world, [both, DONE], ProvaredMiddleware(world.writer, TOOLS), asynchronous=asynchronous)
                self.assertEqual((world.orders, world.messages), ([PAPER], [NOTE]))
                self.assertEqual(sorted(s['action'] for s in stubs(world)), sorted([ORDER, MESSAGE]))

    def test_tools_that_are_not_described_as_they_must_be_are_refused_when_the_agent_is_built(self):
        world = World()
        for tools, where in (({'order_supplies': {'action': ORDER, 'run': len}}, 'run'),
                             ({'order_supplies': 'Not A Name'}, 'action'),
                             ({'order_supplies': 3}, 'order_supplies'),
                             ([('order_supplies', ORDER)], 'tools')):
            with self.subTest(where), self.assertRaises(Refusal) as raised:
                ProvaredMiddleware(world.writer, tools)
            self.assertEqual(raised.exception.code, 'bad-field')
            self.assertIn(where, raised.exception.message)
        with self.assertRaises(Refusal):
            ProvaredMiddleware(world.writer, TOOLS, unlisted='ignore')


if __name__ == '__main__':
    unittest.main()
