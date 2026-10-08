# ProvaredMiddleware: every tool call of a LangChain agent, recorded. The
# agent runs with LangChain's own stand-in model, scripted in advance, inside
# the examples' guard that refuses any connection outside this program.
#
# Run from this package's folder, with the examples' environment:
#   ../../.venv-examples/Scripts/python -m unittest discover -s tests

import asyncio
import os
import sys
import threading
import unittest
from typing import Annotated

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..', '..', 'examples'))

os.environ['LANGSMITH_TRACING'] = 'false'
os.environ['LANGCHAIN_TRACING_V2'] = 'false'

from langchain.agents import create_agent  # noqa: E402
from langchain.agents.middleware import AgentMiddleware  # noqa: E402
from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langchain_core.tools import InjectedToolCallId  # noqa: E402
from langgraph.types import Command  # noqa: E402
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


class Runs:
    """Runs an agent with the stand-in model, inside the guard."""

    def run_agent(self, world, script, middleware, tools=None, asynchronous=False):
        agent = create_agent(ScriptedChatModel(messages=iter(script)),
                             tools=list(make_tools(world).values()) if tools is None else tools,
                             middleware=middleware if isinstance(middleware, list) else [middleware])
        refused.clear()
        try:
            with offline(), tracing_context(enabled=False):
                return asyncio.run(agent.ainvoke(QUESTION)) if asynchronous else agent.invoke(QUESTION)
        finally:
            self.assertEqual(refused, [])


class Middleware(Runs, unittest.TestCase):
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
                # The developer is told too, not only the model.
                with self.assertWarns(RuntimeWarning):
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
                             ({'order_supplies': {'action': ORDER, 'with_': SUPPLIER}}, 'write "with", not "with_"'),
                             ({'order_supplies': {'action': ORDER, 'amout': order_amount}}, 'amout'),
                             ({'order_supplies': 'Not A Name'}, 'action'),
                             ({'order_supplies': 3}, 'order_supplies'),
                             ([('order_supplies', ORDER)], 'tools')):
            with self.subTest(where), self.assertRaises(Refusal) as raised:
                ProvaredMiddleware(world.writer, tools)
            self.assertEqual(raised.exception.code, 'bad-field')
            self.assertIn(where, raised.exception.message)
        with self.assertRaises(Refusal):
            ProvaredMiddleware(world.writer, TOOLS, unlisted='ignore')


class Changing(AgentMiddleware):
    """Changes each call's total to 250 GBP before passing it on, as a person
    reviewing the call might."""

    @staticmethod
    def changed(request):
        return request.override(tool_call={**request.tool_call, 'args': {**request.tool_call['args'], 'total_gbp': 250}})

    def wrap_tool_call(self, request, handler):
        return handler(self.changed(request))

    async def awrap_tool_call(self, request, handler):
        return await handler(self.changed(request))


def in_time(test, work, seconds):
    """Runs work in a thread of its own, and fails the test if it has not ended in time."""
    done, failed = [], []

    def job():
        try:
            done.append(work())
        except BaseException as e:  # noqa: BLE001 -- handed to the test
            failed.append(e)

    thread = threading.Thread(target=job, daemon=True)
    thread.start()
    thread.join(seconds)
    test.assertFalse(thread.is_alive(), f'still running after {seconds} seconds')
    if failed:
        raise failed[0]
    return done[0] if done else None


class AfterTheReview(Runs, unittest.TestCase):
    """The faults the independent review of the package found."""

    def test_it_must_come_last_and_checks_the_call_as_the_tool_receives_it(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                # Last: the changed call is the one checked. Over the limit, so it is not run.
                world = World()
                state = self.run_agent(world, [call('order_supplies', PAPER, 1), DONE],
                                       [Changing(), ProvaredMiddleware(world.writer, TOOLS)], asynchronous=asynchronous)
                self.assertTrue(answers(state)[0].content.startswith('The tool "order_supplies" was not run. With this action the total would be 250 GBP.'))
                self.assertEqual((world.orders, stubs(world)), ([], []))
                # Not last: refused at the first call, before anything is run.
                world = World()
                with self.assertRaises(Refusal) as raised:
                    self.run_agent(world, [call('order_supplies', PAPER, 1), DONE],
                                   [ProvaredMiddleware(world.writer, TOOLS), Changing()], asynchronous=asynchronous)
                self.assertIn('must come last', raised.exception.message)
                self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_many_calls_at_once_and_many_agents_at_once_all_finish(self):
        # The writer runs in threads of its own, not the event loop's shared ones,
        # which LangChain needs for ordinary tools in an asynchronous agent.
        world = World()
        many = AIMessage(content='', tool_calls=[{'name': 'send_message', 'args': {'to': f'Person {i}', 'text': 'Hello.'},
                                                  'id': f'call-{i}', 'type': 'tool_call'} for i in range(40)])
        in_time(self, lambda: self.run_agent(world, [many, DONE], ProvaredMiddleware(world.writer, TOOLS), asynchronous=True), 120)
        self.assertEqual((len(world.messages), len(stubs(world))), (40, 40))

        worlds = [World() for _ in range(20)]
        agents = [create_agent(ScriptedChatModel(messages=iter([call('send_message', NOTE, 1), DONE])),
                               tools=list(make_tools(w).values()), middleware=[ProvaredMiddleware(w.writer, TOOLS)]) for w in worlds]

        async def all_of_them():
            return await asyncio.gather(*(agent.ainvoke(QUESTION) for agent in agents))

        with offline(), tracing_context(enabled=False):
            in_time(self, lambda: asyncio.run(all_of_them()), 120)
        self.assertEqual([len(stubs(w)) for w in worlds], [1] * 20)

    def test_cancelling_a_run_cancels_the_tool_and_frees_the_writer(self):
        world = World()

        async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            await asyncio.sleep(30)
            world.orders.append(item)
            return 'ordered'

        agent = create_agent(ScriptedChatModel(messages=iter([call('order_supplies', PAPER, 1), DONE])),
                             tools=[order_supplies], middleware=[ProvaredMiddleware(world.writer, TOOLS)])

        async def cancelled():
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(agent.ainvoke(QUESTION), 1)
            # While the event loop goes on, as in a server, the writer is free again.
            await asyncio.wait_for(asyncio.to_thread(world.writer.snapshot), 5)

        with offline(), tracing_context(enabled=False):
            in_time(self, lambda: asyncio.run(cancelled()), 30)
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_the_arguments_are_checked_against_the_tool_s_schema_first(self):
        world = World()
        as_text = {'item': 'printer paper', 'quantity': '5', 'total_gbp': '30'}
        state = self.run_agent(world, [call('order_supplies', {'item': 'printer paper', 'quantity': 5}, 1),
                                       call('order_supplies', as_text, 2), DONE], ProvaredMiddleware(world.writer, TOOLS))
        told = answers(state)
        self.assertEqual([m.status for m in told], ['error', 'success'])
        self.assertEqual(told[0].content, 'The tool "order_supplies" was not run. Its arguments do not fit what the tool takes (total_gbp: Field required).')
        # Numbers written as text are read as LangChain reads them, and recorded so.
        [stub] = stubs(world)
        self.assertEqual((world.orders, stub['amount']['value']), ([PAPER], 30))
        self.assertEqual(stub['details'], [{'name': 'arguments', 'sha256': arguments_fingerprint(PAPER)}])

    def test_a_tool_that_answers_with_a_command_has_a_stub_only_if_it_did_not_fail(self):
        for status in ('success', 'error'):
            for asynchronous in (False, True):
                with self.subTest(status=status, asynchronous=asynchronous):
                    world = World()

                    def order_supplies(item: str, quantity: int, total_gbp: int,
                                       tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
                        """Order office supplies."""
                        return Command(update={'messages': [ToolMessage(f'The supplier answered: {status}.', tool_call_id=tool_call_id,
                                                                        status=status)]})

                    self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredMiddleware(world.writer, TOOLS),
                                   tools=[order_supplies], asynchronous=asynchronous)
                    self.assertEqual(len(stubs(world)), 1 if status == 'success' else 0)

    def test_a_refusal_raised_by_the_tool_itself_is_passed_on(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()

                def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
                    """Order office supplies."""
                    world.orders.append(item)
                    raise Refusal('bad-field', 'Raised by the tool, after it placed the order.')

                with self.assertRaises(Refusal) as raised:
                    self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredMiddleware(world.writer, TOOLS),
                                   tools=[order_supplies], asynchronous=asynchronous)
                self.assertEqual(raised.exception.message, 'Raised by the tool, after it placed the order.')
                self.assertEqual((world.orders, stubs(world)), (['printer paper'], []))


if __name__ == '__main__':
    unittest.main()
