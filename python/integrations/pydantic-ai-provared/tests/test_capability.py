# ProvaredCapability: every tool call of a Pydantic AI agent, recorded. The
# agent runs with Pydantic AI's own stand-in model, scripted in advance,
# inside the examples' guard that refuses any connection outside this program.
#
# Run from this package's folder, with the examples' environment:
#   ../../.venv-examples/Scripts/python -m unittest discover -s tests

import asyncio
import dataclasses
import datetime
import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..', '..', 'examples'))

import pydantic_ai  # noqa: E402
from provared import Refusal, arguments_fingerprint, check_book  # noqa: E402
from pydantic_ai import Agent, ModelRetry, ToolFailed, models  # noqa: E402
from pydantic_ai.capabilities import Hooks  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from pydantic_ai_provared import ProvaredCapability  # noqa: E402

from _world import MESSAGE, ORDER, SUPPLIER, World, offline, order_amount, refused  # noqa: E402
from pydantic_ai_example import call, make_tools  # noqa: E402

# No request to any AI service, no instrumentation and no banner.
models.ALLOW_MODEL_REQUESTS = False
Agent.instrument_all(False)
pydantic_ai.BANNER_ENABLED = False

TOOLS = {'order_supplies': {'action': ORDER, 'with': SUPPLIER, 'amount': order_amount}, 'send_message': MESSAGE}
PAPER = {'item': 'printer paper', 'quantity': 5, 'total_gbp': 30}
DESK = {'item': 'standing desk', 'quantity': 1, 'total_gbp': 250}
NOTE = {'to': 'Sam', 'text': 'The paper is ordered.'}
DONE = ModelResponse(parts=[TextPart('Done.')])
QUESTION = 'Order paper and a standing desk.'


def stubs(world):
    return [e['content'] for e in check_book(world.writer.book(), issuer_keys=world.issuer_keys)['entries'] if e['kind'] == 'stub']


def answers(result):
    return [part for message in result.all_messages() for part in message.parts if part.part_kind in ('tool-return', 'retry-prompt')]


class Runs:
    """Runs an agent with the stand-in model, inside the guard."""

    def run_agent(self, world, script, capability, tools=None, asynchronous=False, **more):
        replies = iter(script)
        agent = Agent(FunctionModel(lambda messages, info: next(replies)),
                      tools=list(make_tools(world).values()) if tools is None else tools,
                      capabilities=capability if isinstance(capability, list) else [capability], **more)
        refused.clear()
        try:
            with offline():
                return asyncio.run(agent.run(QUESTION)) if asynchronous else agent.run_sync(QUESTION)
        finally:
            self.assertEqual(refused, [])


class Capability(Runs, unittest.TestCase):
    def test_a_call_inside_the_slip_runs_and_one_over_it_does_not(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                result = self.run_agent(world, [call('order_supplies', PAPER, 1), call('order_supplies', DESK, 2), DONE],
                                        ProvaredCapability(world.writer, TOOLS), asynchronous=asynchronous)
                self.assertEqual(world.orders, [PAPER])
                told = answers(result)
                self.assertEqual([a.outcome for a in told], ['success', 'failed'])
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
                    result = self.run_agent(world, [call('send_message', NOTE, 1), DONE],
                                            ProvaredCapability(world.writer, {'order_supplies': TOOLS['order_supplies']}),
                                            asynchronous=asynchronous)
                self.assertEqual(world.messages, [])
                self.assertEqual(answers(result)[0].content, 'The tool "send_message" was not run. Provared records no tool of that name.')
                world = World()
                self.run_agent(world, [call('send_message', NOTE, 1), DONE],
                               ProvaredCapability(world.writer, {'order_supplies': TOOLS['order_supplies']}, unlisted='run'),
                               asynchronous=asynchronous)
                self.assertEqual((world.messages, stubs(world)), ([NOTE], []))

    def test_arguments_that_do_not_fit_never_reach_the_writer(self):
        # Pydantic AI checks the arguments against the tool's schema before the capability.
        world = World()
        result = self.run_agent(world, [call('order_supplies', {**PAPER, 'quantity': 'many'}, 1), DONE],
                                ProvaredCapability(world.writer, TOOLS))
        self.assertEqual([a.part_kind for a in answers(result)], ['retry-prompt'])
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_tool_that_fails_or_asks_to_be_retried_leaves_no_stub(self):
        def failing(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            raise ValueError('the supplier is closed')

        def retrying(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            raise ModelRetry('Give the quantity in boxes.')

        def reporting(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            raise ToolFailed('The supplier has no paper.')

        world = World()
        result = self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredCapability(world.writer, TOOLS),
                                tools=[dataclasses.replace(pydantic_ai.Tool(reporting), name='order_supplies')])
        self.assertEqual([(a.outcome, a.content) for a in answers(result)], [('failed', 'The supplier has no paper.')])
        self.assertEqual(stubs(world), [])

        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                with self.assertRaises(ValueError):
                    self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredCapability(world.writer, TOOLS),
                                   tools=[dataclasses.replace(pydantic_ai.Tool(failing), name='order_supplies')],
                                   asynchronous=asynchronous)
                self.assertEqual(stubs(world), [])
                world = World()
                result = self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredCapability(world.writer, TOOLS),
                                        tools=[dataclasses.replace(pydantic_ai.Tool(retrying), name='order_supplies')],
                                        asynchronous=asynchronous)
                self.assertEqual([a.part_kind for a in answers(result)], ['retry-prompt'])
                self.assertEqual(stubs(world), [])

    def test_arguments_that_are_not_plain_data_are_not_run_and_the_model_is_told(self):
        world = World()
        ran = []

        def order_supplies(item: str, quantity: int, total_gbp: int, deliver_on: datetime.date) -> str:
            """Order office supplies."""
            ran.append(deliver_on)
            return 'ordered'

        result = self.run_agent(world, [call('order_supplies', {**PAPER, 'deliver_on': '2026-10-09'}, 1), DONE],
                                ProvaredCapability(world.writer, TOOLS), tools=[order_supplies])
        [told] = answers(result)
        self.assertEqual(told.outcome, 'failed')
        self.assertTrue(told.content.startswith('The tool "order_supplies" was not run. The arguments of the tool "order_supplies" must be plain data'))
        self.assertEqual((ran, stubs(world)), ([], []))

    def test_a_tool_that_calls_the_writer_is_refused_at_once(self):
        # Also where the tool runs on the event loop and the writer in a thread of its own.
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()

                async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
                    """Order office supplies."""
                    world.writer.act({'action': MESSAGE}, lambda: None)
                    return 'ordered'

                with self.assertRaises(RuntimeError) as raised:
                    self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredCapability(world.writer, TOOLS),
                                   tools=[order_supplies], asynchronous=asynchronous)
                self.assertIn('from inside an action', str(raised.exception))
                self.assertEqual(stubs(world), [])

    def test_two_calls_in_one_reply_are_both_recorded(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                both = ModelResponse(parts=[ToolCallPart('order_supplies', PAPER, tool_call_id='call-1'),
                                            ToolCallPart('send_message', NOTE, tool_call_id='call-2')])
                self.run_agent(world, [both, DONE], ProvaredCapability(world.writer, TOOLS), asynchronous=asynchronous)
                self.assertEqual((world.orders, world.messages), ([PAPER], [NOTE]))
                self.assertEqual(sorted(s['action'] for s in stubs(world)), sorted([ORDER, MESSAGE]))

    def test_the_tool_for_the_final_output_is_never_refused(self):
        world = World()
        result = self.run_agent(world, [ModelResponse(parts=[ToolCallPart('final_result', {'response': 3}, tool_call_id='call-1')])],
                                ProvaredCapability(world.writer, TOOLS), output_type=int)
        self.assertEqual((result.output, stubs(world)), (3, []))

    def test_tools_that_are_not_described_as_they_must_be_are_refused_when_the_capability_is_made(self):
        world = World()
        for tools, where in (({'order_supplies': {'action': ORDER, 'run': len}}, 'run'),
                             ({'order_supplies': {'action': ORDER, 'with_': SUPPLIER}}, 'write "with", not "with_"'),
                             ({'order_supplies': {'action': ORDER, 'amout': order_amount}}, 'amout'),
                             ({'order_supplies': 'Not A Name'}, 'action'),
                             ({'order_supplies': 3}, 'order_supplies'),
                             ([('order_supplies', ORDER)], 'tools')):
            with self.subTest(where), self.assertRaises(Refusal) as raised:
                ProvaredCapability(world.writer, tools)
            self.assertEqual(raised.exception.code, 'bad-field')
            self.assertIn(where, raised.exception.message)
        with self.assertRaises(Refusal):
            ProvaredCapability(world.writer, TOOLS, unlisted='ignore')


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

    def test_a_change_another_capability_makes_is_the_call_checked_wherever_it_stands(self):
        async def changed(ctx, *, call, tool_def, args):
            return {**args, 'total_gbp': 250}

        for first in (True, False):
            with self.subTest(provared_first=first):
                world = World()
                ours, hooks = ProvaredCapability(world.writer, TOOLS), Hooks(before_tool_execute=changed)
                result = self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], [ours, hooks] if first else [hooks, ours])
                [told] = answers(result)
                self.assertEqual(told.outcome, 'failed')
                self.assertTrue(told.content.startswith('The tool "order_supplies" was not run. With this action the total would be 250 GBP.'))
                self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_tool_that_ran_keeps_its_stub_when_its_result_is_then_sent_back(self):
        async def again(ctx, *, call, tool_def, args, result):
            raise ModelRetry('Try again.')

        world = World()
        self.run_agent(world, [call('order_supplies', PAPER, 1), DONE],
                       [ProvaredCapability(world.writer, TOOLS), Hooks(after_tool_execute=again)])
        self.assertEqual((len(world.orders), len(stubs(world))), (1, 1))

    def test_an_error_another_capability_turns_into_an_answer_leaves_no_stub(self):
        def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            raise ValueError('the supplier is closed')

        async def answered(ctx, *, call, tool_def, args, error):
            return 'The supplier is closed today.'

        world = World()
        result = self.run_agent(world, [call('order_supplies', PAPER, 1), DONE],
                                [ProvaredCapability(world.writer, TOOLS), Hooks(tool_execute_error=answered)], tools=[order_supplies])
        self.assertEqual([a.content for a in answers(result)], ['The supplier is closed today.'])
        self.assertEqual(stubs(world), [])

    def test_a_tool_s_own_time_limit_cancels_it_and_leaves_no_stub(self):
        world = World()

        async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            await asyncio.sleep(30)
            world.orders.append(item)
            return 'ordered'

        result = in_time(self, lambda: self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredCapability(world.writer, TOOLS),
                                                      tools=[pydantic_ai.Tool(order_supplies, timeout=1)]), 30)
        self.assertEqual([a.part_kind for a in answers(result)], ['retry-prompt'])
        in_time(self, world.writer.snapshot, 5)
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_many_calls_at_once_whose_tools_use_threads_all_finish(self):
        world = World()

        async def send_message(to: str, text: str) -> str:
            """Send a short message."""
            await asyncio.to_thread(world.messages.append, {'to': to, 'text': text})
            return 'sent'

        many = ModelResponse(parts=[ToolCallPart('send_message', {'to': f'Person {i}', 'text': 'Hello.'}, tool_call_id=f'call-{i}')
                                    for i in range(40)])
        in_time(self, lambda: self.run_agent(world, [many, DONE], ProvaredCapability(world.writer, TOOLS),
                                             tools=[send_message], asynchronous=True), 120)
        self.assertEqual((len(world.messages), len(stubs(world))), (40, 40))

    def test_cancelling_a_run_cancels_the_tool_and_frees_the_writer(self):
        world = World()

        async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            await asyncio.sleep(30)
            world.orders.append(item)
            return 'ordered'

        replies = iter([call('order_supplies', PAPER, 1), DONE])
        agent = Agent(FunctionModel(lambda messages, info: next(replies)), tools=[order_supplies],
                      capabilities=[ProvaredCapability(world.writer, TOOLS)])

        async def cancelled():
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(agent.run(QUESTION), 1)
            # While the event loop goes on, as in a server, the writer is free again.
            await asyncio.wait_for(asyncio.to_thread(world.writer.snapshot), 5)

        with offline():
            in_time(self, lambda: asyncio.run(cancelled()), 30)
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_refusal_raised_by_the_tool_itself_is_passed_on(self):
        world = World()

        def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            world.orders.append(item)
            raise Refusal('bad-field', 'Raised by the tool, after it placed the order.')

        with self.assertRaises(Refusal) as raised:
            self.run_agent(world, [call('order_supplies', PAPER, 1), DONE], ProvaredCapability(world.writer, TOOLS), tools=[order_supplies])
        self.assertEqual(raised.exception.message, 'Raised by the tool, after it placed the order.')
        self.assertEqual((world.orders, stubs(world)), (['printer paper'], []))


if __name__ == '__main__':
    unittest.main()
