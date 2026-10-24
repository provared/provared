# ProvaredToolHook: every tool call of an Agno agent, recorded. Agno offers
# no stand-in model, so the agent runs with a small one written here on
# Agno's own model class, which gives replies scripted in advance and calls
# no AI service. It runs inside the examples' guard that refuses any
# connection outside this program, with Agno's telemetry switched off.
#
# Run from this package's folder, with its own environment:
#   .venv/Scripts/python -m unittest discover -s tests

import asyncio
import copy
import datetime
import inspect
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import dataclass, field
from typing import Annotated, Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..', '..', 'examples'))

# No telemetry, before Agno is imported; each agent below also says so itself.
os.environ['AGNO_TELEMETRY'] = 'false'
# Agno logs each failed tool call with its traceback. The tests read what
# the model is handed instead.
logging.disable(logging.CRITICAL)

from agno.agent import Agent  # noqa: E402
from agno.exceptions import RetryAgentRun, StopAgentRun  # noqa: E402
from agno.models.base import Model  # noqa: E402
from agno.models.response import ModelResponse  # noqa: E402
from agno.team import Team  # noqa: E402
from agno.tools import tool  # noqa: E402
from agno.tools.function import Function, FunctionCall  # noqa: E402
from provared import Refusal, arguments_fingerprint, check_book  # noqa: E402
from pydantic import AfterValidator, BaseModel, Field, SecretStr  # noqa: E402

from provared_agno import ProvaredToolHook  # noqa: E402

from _world import MESSAGE, ORDER, SUPPLIER, World, offline, order_amount, refused  # noqa: E402

TOOLS = {'order_supplies': {'action': ORDER, 'with': SUPPLIER, 'amount': order_amount}, 'send_message': MESSAGE}
PAPER = {'item': 'printer paper', 'quantity': 5, 'total_gbp': 30}
DESK = {'item': 'standing desk', 'quantity': 1, 'total_gbp': 250}
NOTE = {'to': 'Sam', 'text': 'The paper is ordered.'}
DONE = 'Done.'
QUESTION = 'Order paper and a standing desk.'
SHARED_THREADS = min(32, (os.cpu_count() or 1) + 4)


class Client:
    """An object of the program's own, with no JSON form."""


DEFAULT_CLIENT = Client()


class Delivery(BaseModel):
    """An address a model gives by another name, with a field that pydantic
    leaves out when it writes JSON."""

    post_code: str = Field(alias='postCode')
    left_at: str = Field(default='the front door', exclude=True)


@dataclass
class ScriptedModel(Model):
    """A stand-in model on Agno's own model class: it gives the replies it
    is handed, one after another, and calls no AI service."""

    id: str = 'scripted'
    name: str = 'Scripted stand-in'
    provider: str = 'Stand-in'
    script: List[Any] = field(default_factory=list)

    def _next(self, messages=None):
        reply = self.script.pop(0)
        if callable(reply):
            # A reply that reads the conversation so far, such as a task's id.
            reply = reply(messages or [])
        return ModelResponse(role='assistant', content=reply) if isinstance(reply, str) else reply

    def invoke(self, *args, **kwargs):
        return self._next(kwargs.get('messages'))

    async def ainvoke(self, *args, **kwargs):
        return self._next(kwargs.get('messages'))

    def invoke_stream(self, *args, **kwargs):
        yield self._next()

    async def ainvoke_stream(self, *args, **kwargs):
        yield self._next()

    def _parse_provider_response(self, response, **kwargs):
        return response

    def _parse_provider_response_delta(self, response):
        return response


def calls(*named):
    """One reply of the model that asks for these tool calls, each (name, arguments)."""
    return ModelResponse(role='assistant', tool_calls=[
        {'id': f'call-{i}', 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(args)}}
        for i, (name, args) in enumerate(named)])


def call(name, args):
    return calls((name, args))


def hand_the_task_over(name):
    """A reply that hands over the task made before it, by the id Agno gave
    it, with execute_task or execute_tasks_parallel."""

    def reply(messages):
        made = [m.content for m in messages if getattr(m, 'role', None) == 'tool' and isinstance(m.content, str) and 'Task created' in m.content]
        task_id = re.search(r'\[([0-9a-f]+)\]', made[-1]).group(1) if made else 'none'
        return call(name, {'task_id': task_id, 'member_id': 'helper'} if name == 'execute_task' else {'task_ids': [task_id]})

    return reply


def make_tools(world):
    """The agent's tools: ordinary functions, with type hints and docstrings.
    They write into the invented world, so a reader can see what ran."""

    def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
        """Order office supplies from the stationery supplier."""
        world.orders.append({'item': item, 'quantity': quantity, 'total_gbp': total_gbp})
        return f'Ordered {quantity} x {item} for {total_gbp} GBP.'

    def send_message(to: str, text: str) -> str:
        """Send a short message to a person in the office."""
        world.messages.append({'to': to, 'text': text})
        return f'Message sent to {to}.'

    return [order_supplies, send_message]


def stubs(world):
    return [e['content'] for e in check_book(world.writer.book(), issuer_keys=world.issuer_keys)['entries'] if e['kind'] == 'stub']


def answers(result):
    """What the model was handed for each tool call: (answer, whether it failed)."""
    return [(m.content, m.tool_call_error) for m in result.messages if m.role == 'tool']


def make_agent(world, script, hooks, tools=None, **more):
    """An agent with the stand-in model. hooks: a ProvaredToolHook, given as
    its README says, or the agent's tool hooks as they are to be given."""
    return Agent(model=ScriptedModel(script=list(script)), tools=make_tools(world) if tools is None else tools,
                 tool_hooks=hooks.hooks if isinstance(hooks, ProvaredToolHook) else hooks, telemetry=False, **more)


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


class Runs:
    """Runs an agent with the stand-in model, inside the guard."""

    def run_agent(self, world, script, hooks, tools=None, asynchronous=False, agent=None):
        agent = make_agent(world, script, hooks, tools) if agent is None else agent
        refused.clear()
        try:
            with offline():
                return asyncio.run(agent.arun(QUESTION)) if asynchronous else agent.run(QUESTION)
        finally:
            self.assertEqual(refused, [])


class ToolHook(Runs, unittest.TestCase):
    def test_a_call_inside_the_slip_runs_and_one_over_it_does_not(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                result = self.run_agent(world, [call('order_supplies', PAPER), call('order_supplies', DESK), DONE],
                                        ProvaredToolHook(world.writer, TOOLS), asynchronous=asynchronous)
                self.assertEqual(world.orders, [PAPER])
                told = answers(result)
                self.assertEqual(told[0], ('Ordered 5 x printer paper for 30 GBP.', False))
                self.assertTrue(told[1][1])
                self.assertTrue(told[1][0].startswith('The tool "order_supplies" was not run. With this action the total would be 280 GBP.'))
                [stub] = stubs(world)
                self.assertEqual((stub['action'], stub['with'], stub['amount']), (ORDER, SUPPLIER, {'unit': 'GBP', 'value': 30}))
                self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(PAPER)}])
                summary = check_book(world.writer.book(), issuer_keys=world.issuer_keys)['summary']
                self.assertTrue(summary['intact'] and summary['withinSlips'])

    def test_an_asynchronous_tool_is_recorded_as_an_ordinary_one_is(self):
        # Agno runs an asynchronous tool in an asynchronous run only.
        world = World()

        async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies from the stationery supplier."""
            await asyncio.sleep(0)
            world.orders.append({'item': item, 'quantity': quantity, 'total_gbp': total_gbp})
            return 'ordered'

        result = self.run_agent(world, [call('order_supplies', PAPER), call('order_supplies', DESK), DONE],
                                ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies], asynchronous=True)
        self.assertEqual(world.orders, [PAPER])
        self.assertEqual([failed for _, failed in answers(result)], [False, True])
        [stub] = stubs(world)
        self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(PAPER)}])

    def test_a_tool_that_is_not_described_is_refused_or_run_unrecorded(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                # The developer is told too, not only the model.
                with self.assertWarns(RuntimeWarning):
                    result = self.run_agent(world, [call('send_message', NOTE), DONE],
                                            ProvaredToolHook(world.writer, {'order_supplies': TOOLS['order_supplies']}),
                                            asynchronous=asynchronous)
                self.assertEqual(world.messages, [])
                self.assertEqual(answers(result), [('The tool "send_message" was not run. Provared records no tool of that name.', True)])
                world = World()
                self.run_agent(world, [call('send_message', NOTE), DONE],
                               ProvaredToolHook(world.writer, {'order_supplies': TOOLS['order_supplies']}, unlisted='run'),
                               asynchronous=asynchronous)
                self.assertEqual((world.messages, stubs(world)), ([NOTE], []))

    def test_a_tool_that_fails_leaves_no_stub_and_agno_tells_the_model(self):
        def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            raise ValueError('the supplier is closed')

        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                result = self.run_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS),
                                        tools=[order_supplies], asynchronous=asynchronous)
                self.assertEqual(answers(result), [('the supplier is closed', True)])
                self.assertEqual(stubs(world), [])

    def test_a_tool_that_calls_the_writer_is_refused_at_once(self):
        # Also where the tool runs in a thread, or on the event loop, and the
        # writer in a thread of its own. Without the writer's mark the call
        # would wait for ever, so the test has a time limit.
        for asynchronous in (False, True):
            world = World()

            def ordinary(item: str, quantity: int, total_gbp: int) -> str:
                """Order office supplies."""
                world.writer.act({'action': MESSAGE}, lambda: None)
                return 'ordered'

            async def on_the_loop(item: str, quantity: int, total_gbp: int) -> str:
                """Order office supplies."""
                world.writer.act({'action': MESSAGE}, lambda: None)
                return 'ordered'

            tools = [tool(name='order_supplies')(ordinary)] + ([tool(name='order_supplies')(on_the_loop)] if asynchronous else [])
            for order_supplies in tools:
                with self.subTest(asynchronous=asynchronous, tool=order_supplies.entrypoint.__name__):
                    result = in_time(self, lambda: self.run_agent(world, [call('order_supplies', PAPER), DONE],
                                                                  ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies],
                                                                  asynchronous=asynchronous), 30)
                    [(told, failed)] = answers(result)
                    self.assertTrue(failed)
                    self.assertIn('from inside an action', told)
                    self.assertEqual(stubs(world), [])

    def test_two_calls_in_one_reply_are_both_recorded(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                self.run_agent(world, [calls(('order_supplies', PAPER), ('send_message', NOTE)), DONE],
                               ProvaredToolHook(world.writer, TOOLS), asynchronous=asynchronous)
                self.assertEqual((world.orders, world.messages), ([PAPER], [NOTE]))
                self.assertEqual(sorted(s['action'] for s in stubs(world)), sorted([ORDER, MESSAGE]))

    def test_tools_that_are_not_described_as_they_must_be_are_refused_when_the_hook_is_made(self):
        world = World()
        for tools, where in (({'order_supplies': {'action': ORDER, 'run': len}}, 'run'),
                             ({'order_supplies': {'action': ORDER, 'with_': SUPPLIER}}, 'write "with", not "with_"'),
                             ({'order_supplies': {'action': ORDER, 'amout': order_amount}}, 'amout'),
                             ({'order_supplies': 'Not A Name'}, 'action'),
                             ({'order_supplies': 3}, 'order_supplies'),
                             ([('order_supplies', ORDER)], 'tools')):
            with self.subTest(where), self.assertRaises(Refusal) as raised:
                ProvaredToolHook(world.writer, tools)
            self.assertEqual(raised.exception.code, 'bad-field')
            self.assertIn(where, raised.exception.message)
        with self.assertRaises(Refusal):
            ProvaredToolHook(world.writer, TOOLS, unlisted='ignore')


class TheArguments(Runs, unittest.TestCase):
    """What is checked and recorded is what Agno hands the tool: defaults
    filled in, values converted by the type hints, in their JSON form."""

    def test_defaults_are_filled_in_and_values_converted_before_the_check(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                received, seen = [], []

                def order_supplies(item: str, quantity: int = 1, total_gbp: int = 95, express: bool = False) -> str:
                    """Order office supplies."""
                    received.append({'item': item, 'quantity': quantity, 'total_gbp': total_gbp, 'express': express})
                    return 'ordered'

                def amount(args):
                    seen.append(args)
                    return {'unit': 'GBP', 'value': args['total_gbp']}

                read = {'item': 'desk', 'quantity': 1, 'total_gbp': 95, 'express': True}
                self.run_agent(world, [call('order_supplies', {'item': 'desk', 'express': 'yes'}), DONE],
                               ProvaredToolHook(world.writer, {'order_supplies': {'action': ORDER, 'with': SUPPLIER, 'amount': amount}}),
                               tools=[order_supplies], asynchronous=asynchronous)
                [stub] = stubs(world)
                self.assertEqual((seen, received), ([read], [read]))
                self.assertEqual(stub['amount'], {'unit': 'GBP', 'value': 95})
                self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(read)}])

    def test_where_agno_converts_nothing_the_tool_is_handed_the_arguments_as_given(self):
        # Agno does not convert the arguments of a tool that takes the agent,
        # and neither does the hook: the tool is handed what it would be handed without it.
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                received = []

                def order_supplies(item: str, quantity: int, total_gbp: int, agent: Agent) -> str:
                    """Order office supplies."""
                    received.append({'item': item, 'quantity': quantity, 'total_gbp': total_gbp})
                    return 'ordered'

                given = {'item': 'printer paper', 'quantity': '5', 'total_gbp': 30}
                self.run_agent(world, [call('order_supplies', given), DONE],
                               ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies], asynchronous=asynchronous)
                [stub] = stubs(world)
                self.assertEqual(received, [given])
                self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(given)}])

    def test_the_tool_is_handed_exactly_what_it_would_be_handed_without_the_hook(self):
        # A secret is handed as itself, and fingerprinted by its value; a
        # model whose field is named by another name is read as Agno reads it.
        for hooked in (False, True):
            with self.subTest(hooked=hooked):
                world = World()
                received = []

                def send_message(to: str, text: str, token: SecretStr, delivery: Delivery) -> str:
                    """Send a message with the person's own token, to a delivery address."""
                    received.append((token.get_secret_value(), delivery.post_code))
                    return 'sent'

                given = {'to': 'Sam', 'text': 'Hi', 'token': 'tok-123', 'delivery': {'postCode': 'BS1 4DJ'}}
                self.run_agent(world, [call('send_message', given), DONE], ProvaredToolHook(world.writer, TOOLS) if hooked else [],
                               tools=[send_message])
                self.assertEqual(received, [('tok-123', 'BS1 4DJ')])
                if hooked:
                    [stub] = stubs(world)
                    # Every field of the model, by the name it is read by, its default filled in.
                    read = {**given, 'delivery': {'postCode': 'BS1 4DJ', 'left_at': 'the front door'}}
                    self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(read)}])

    def test_a_field_that_pydantic_leaves_out_of_json_is_recorded_all_the_same(self):
        # pydantic leaves out a field marked "exclude" when it writes JSON; the record does not.
        world = World()
        received = []

        def send_message(to: str, text: str, delivery: Delivery) -> str:
            """Send a message to a delivery address."""
            received.append(delivery.left_at)
            return 'sent'

        given = {'to': 'Sam', 'text': 'Hi', 'delivery': {'postCode': 'BS1 4DJ', 'left_at': 'the back door'}}
        self.run_agent(world, [call('send_message', given), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[send_message])
        [stub] = stubs(world)
        self.assertEqual(received, ['the back door'])
        self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(given)}])

    def test_a_dict_whose_names_are_numbers_is_recorded_with_its_names_as_text(self):
        world = World()
        received = []

        def send_message(to: str, counts: Dict[int, int]) -> str:
            """Send counts by product number."""
            received.append(counts)
            return 'sent'

        given = {'to': 'Sam', 'counts': {'101': 2, '102': 1}}
        self.run_agent(world, [call('send_message', given), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[send_message])
        [stub] = stubs(world)
        self.assertEqual(received, [{101: 2, 102: 1}])
        self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(given)}])

    def test_a_default_of_the_tool_s_own_with_no_json_form_is_left_out_of_the_record(self):
        # The tool's own object, not the model's: read back, the call takes it again.
        world = World()
        received = []

        def send_message(to: str, text: str, client: Client = DEFAULT_CLIENT) -> str:
            """Send a message through the office's client."""
            received.append(client)
            return 'sent'

        self.run_agent(world, [call('send_message', NOTE), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[send_message])
        [stub] = stubs(world)
        self.assertEqual(received, [DEFAULT_CLIENT])
        self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(NOTE)}])

    def test_a_value_with_no_json_form_that_the_record_cannot_fix_is_refused_not_changed(self):
        # A new object for each call: the record could not say what the tool was handed.
        world = World()
        received = []

        def send_message(to: str, text: str, client: Client = Field(default_factory=Client)) -> str:
            """Send a message through a client made for the call."""
            received.append(client)
            return 'sent'

        result = self.run_agent(world, [call('send_message', NOTE), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[send_message])
        [(told, failed)] = answers(result)
        self.assertTrue(failed)
        self.assertIn('which has no JSON form', told)
        self.assertEqual((received, stubs(world)), ([], []))

    def test_a_value_made_while_the_call_is_read_is_the_one_the_tool_is_handed(self):
        # A default made afresh for each call is made once, recorded, and handed over.
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                received = []

                def order_supplies(item: str, quantity: int, total_gbp: int,
                                   reference: str = Field(default_factory=lambda: uuid.uuid4().hex)) -> str:
                    """Order office supplies."""
                    received.append(reference)
                    return 'ordered'

                self.run_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS),
                               tools=[order_supplies], asynchronous=asynchronous)
                [stub] = stubs(world)
                self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint({**PAPER, 'reference': received[0]})}])

    def test_a_field_the_person_leaves_out_is_recorded_with_its_default(self):
        # Agno 3.1 hands such a field as None; a later Agno might leave it out,
        # and the tool would then be handed its default, which is recorded too.
        world = World()
        received = []

        def order_supplies(item: str, quantity: int, total_gbp: int = 95) -> str:
            """Order office supplies."""
            received.append(total_gbp)
            return 'ordered'

        ours = ProvaredToolHook(world.writer, TOOLS)
        agent = make_agent(world, [], ours)
        function = Function.from_callable(order_supplies)
        function.tool_hooks = list(ours.hooks)
        function._agent = agent
        function.process_entrypoint()
        function.user_input_fields = ['total_gbp']
        function.parameters = {'type': 'object', 'properties': {'item': {'type': 'string'}, 'quantity': {'type': 'integer'}},
                               'required': ['item', 'quantity']}
        outcome = FunctionCall(function=function, arguments={'item': 'desk', 'quantity': 1}).execute()
        self.assertEqual((outcome.status, received), ('success', [95]))
        [stub] = stubs(world)
        self.assertEqual(stub['amount'], {'unit': 'GBP', 'value': 95})

    def test_a_value_json_cannot_hold_is_recorded_in_its_json_form(self):
        world = World()
        received = []

        def order_supplies(item: str, quantity: int, total_gbp: int, deliver_on: Optional[datetime.date] = None) -> str:
            """Order office supplies."""
            received.append(deliver_on)
            return 'ordered'

        self.run_agent(world, [call('order_supplies', {**PAPER, 'deliver_on': '2026-10-09'}), DONE],
                       ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies])
        [stub] = stubs(world)
        self.assertEqual(received, [datetime.date(2026, 10, 9)])
        self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint({**PAPER, 'deliver_on': '2026-10-09'})}])

    def test_arguments_that_do_not_fit_the_tool_are_not_run_and_the_model_is_told(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                result = self.run_agent(world, [call('order_supplies', {**PAPER, 'quantity': 'many'}),
                                                call('order_supplies', {'item': 'printer paper', 'quantity': 5}), DONE],
                                        ProvaredToolHook(world.writer, TOOLS), asynchronous=asynchronous)
                told = answers(result)
                self.assertTrue(all(failed for _, failed in told))
                self.assertTrue(told[0][0].startswith('The tool "order_supplies" was not run. Its arguments do not fit what the tool takes (quantity:'))
                self.assertIn('total_gbp: Missing required', told[1][0])
                self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_value_the_person_fills_in_is_checked_and_recorded(self):
        # Agno asks the person for the total, which the model does not see.
        for total, asynchronous in ((30, False), (30, True), (250, False)):
            with self.subTest(total=total, asynchronous=asynchronous):
                world = World()

                @tool(name='order_supplies', requires_user_input=True, user_input_fields=['total_gbp'])
                def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
                    """Order office supplies."""
                    world.orders.append(total_gbp)
                    return 'ordered'

                agent = make_agent(world, [call('order_supplies', {'item': 'desk', 'quantity': 1}), DONE, DONE],
                                   ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies])
                refused.clear()
                with offline():
                    paused = asyncio.run(agent.arun(QUESTION)) if asynchronous else agent.run(QUESTION)
                    for asked in paused.tools:
                        for one in asked.user_input_schema:
                            if one.name == 'total_gbp':
                                one.value = total
                    asyncio.run(agent.acontinue_run(run_response=paused)) if asynchronous else agent.continue_run(run_response=paused)
                self.assertEqual(refused, [])
                read = {'item': 'desk', 'quantity': 1, 'total_gbp': total}
                if total > 100:
                    self.assertEqual((world.orders, stubs(world)), ([], []))
                    continue
                [stub] = stubs(world)
                self.assertEqual((world.orders, stub['amount']['value']), ([total], total))
                self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(read)}])

    def test_input_the_tool_refuses_through_its_type_hints_leaves_no_stub(self):
        # The way the README gives to refuse the model's input with no stub.
        world = World()
        ran = []

        def order_supplies(item: str, quantity: int, total_gbp: Annotated[int, Field(le=50)]) -> str:
            """Order office supplies, at most 50 GBP at a time."""
            ran.append(item)
            return 'ordered'

        result = self.run_agent(world, [call('order_supplies', {**PAPER, 'total_gbp': 90}), DONE], ProvaredToolHook(world.writer, TOOLS),
                                tools=[order_supplies])
        [(told, failed)] = answers(result)
        self.assertTrue(failed)
        self.assertIn('Its arguments do not fit what the tool takes (total_gbp: Input should be less than or equal to 50)', told)
        self.assertEqual((ran, stubs(world)), ([], []))

    def test_a_value_that_reads_differently_each_time_is_refused(self):
        # Agno would read again the form recorded, and hand the tool something else.
        world = World()
        received = []

        def order_supplies(item: str, quantity: Annotated[int, AfterValidator(lambda n: n + 1)], total_gbp: int) -> str:
            """Order office supplies."""
            received.append(quantity)
            return 'ordered'

        result = self.run_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies])
        [(told, failed)] = answers(result)
        self.assertTrue(failed)
        self.assertIn('do not read back as the values the tool would be handed', told)
        self.assertEqual((received, stubs(world)), ([], []))

    def test_values_that_would_reach_the_tool_other_than_as_recorded_are_refused(self):
        # Two ways, each caught by one half of the check. (1) The values handed
        # over would be read again as something else: here a default that a
        # type hint doubles when it reads it, although it reads its JSON form
        # as itself. (2) The record, read back, would give something else than
        # the values handed over: here a tuple that the tool's own pre_hook puts
        # in, where the type is Any, written as a list in JSON.
        from decimal import Decimal

        from pydantic import BeforeValidator

        def doubled_when_read_again(value):
            return value if isinstance(value, str) else value * 2

        def tag_it(fc):
            fc.arguments['tags'] = ('urgent',)

        for case in ('read again', 'record read back'):
            with self.subTest(case=case):
                world = World()
                received = []
                if case == 'read again':
                    def order_supplies(item: str, quantity: int, total_gbp: int,
                                       weight_kg: Annotated[Decimal, BeforeValidator(doubled_when_read_again)] = Decimal('1')) -> str:
                        """Order office supplies."""
                        received.append(weight_kg)
                        return 'ordered'

                    tools, asked = [order_supplies], call('order_supplies', PAPER)
                else:
                    def send_message(to: str, text: str, tags: Any = None) -> str:
                        """Send a short message."""
                        received.append(tags)
                        return 'sent'

                    tools, asked = [tool(name='send_message', pre_hook=tag_it)(send_message)], call('send_message', NOTE)
                result = self.run_agent(world, [asked, DONE], ProvaredToolHook(world.writer, TOOLS), tools=tools)
                [(told, failed)] = answers(result)
                self.assertTrue(failed)
                self.assertIn('do not read back as the values the tool would be handed', told)
                self.assertEqual((received, stubs(world)), ([], []))

    def test_a_tool_that_takes_any_named_argument_is_handed_the_others_as_given(self):
        world = World()
        received = []

        def send_message(to: str, **more) -> str:
            """Send a short message."""
            received.append({'to': to, **more})
            return 'sent'

        function = Function.from_callable(send_message)
        function.parameters = {'type': 'object', 'properties': {'to': {'type': 'string'}, 'text': {'type': 'string'}}, 'required': ['to']}
        self.run_agent(world, [call('send_message', NOTE), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[function])
        [stub] = stubs(world)
        self.assertEqual(received, [NOTE])
        self.assertEqual(stub['details'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(NOTE)}])


class TeamsAndAgnosOwnTools(Runs, unittest.TestCase):
    def run_team(self, team, asynchronous):
        refused.clear()
        with offline():
            result = asyncio.run(team.arun(QUESTION)) if asynchronous else team.run(QUESTION)
        self.assertEqual(refused, [])
        return result

    def test_a_team_hands_a_task_to_a_member_that_carries_hooks_of_the_same_writer(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                member = Agent(name='Helper', id='helper', telemetry=False, tools=make_tools(world),
                               model=ScriptedModel(script=[call('send_message', NOTE), DONE]),
                               tool_hooks=ProvaredToolHook(world.writer, TOOLS).hooks)
                team = Team(name='Office', members=[member], telemetry=False,
                            model=ScriptedModel(script=[call('delegate_task_to_member', {'member_id': 'helper', 'task': 'Tell Sam.'}), DONE]),
                            tool_hooks=ProvaredToolHook(world.writer, TOOLS).hooks)
                result = self.run_team(team, asynchronous)
                self.assertFalse(any(failed for _, failed in answers(result)))
                # The hand-over itself leaves no stub; what the member did does.
                self.assertEqual((world.messages, [s['action'] for s in stubs(world)]), ([NOTE], [MESSAGE]))

    def test_a_hand_over_to_a_member_whose_actions_would_not_be_recorded_is_refused(self):
        for hooks, why in ((None, 'carries no tool hooks of this stub writer'), ('another writer', 'carries no tool hooks of this stub writer')):
            for hand_over, asked in (('delegate_task_to_member', {'member_id': 'helper', 'task': 'Order a desk.'}),
                                     ('delegate_task_to_members', {'task': 'Order a desk.'})):
                for asynchronous in (False, True):
                    with self.subTest(hooks=hooks, hand_over=hand_over, asynchronous=asynchronous):
                        world = World()
                        member = Agent(name='Helper', id='helper', telemetry=False, tools=make_tools(world),
                                       model=ScriptedModel(script=[call('order_supplies', DESK), DONE]),
                                       tool_hooks=ProvaredToolHook(World().writer, TOOLS).hooks if hooks else None)
                        team = Team(name='Office', members=[member], telemetry=False,
                                    delegate_to_all_members=hand_over == 'delegate_task_to_members',
                                    model=ScriptedModel(script=[call(hand_over, asked), DONE]),
                                    tool_hooks=ProvaredToolHook(world.writer, TOOLS).hooks)
                        with self.assertWarns(RuntimeWarning):
                            result = self.run_team(team, asynchronous)
                        [(told, failed)] = answers(result)
                        self.assertTrue(failed)
                        self.assertIn(f'The tool "{hand_over}" was not run. The member "helper" {why}', told)
                        self.assertIn(f'or describe "{hand_over}"', told)
                        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_member_on_another_service_is_never_taken_to_carry_the_hooks(self):
        from agno.agent.remote import RemoteAgent

        from provared_agno import _hand_over_not_recorded

        world = World()
        ours = ProvaredToolHook(world.writer, TOOLS)
        refused.clear()
        with offline():
            # Made without its connection, which needs Agno's web server package.
            away = RemoteAgent.__new__(RemoteAgent)
            away.agent_id = 'helper'
            away.tool_hooks = ours.hooks  # even so

            class OneMember:
                def _find_member_by_id(self, member_id, run_context=None):
                    return (0, away) if member_id == 'helper' else None

            why = _hand_over_not_recorded(ours, 'delegate_task_to_member', None, {'member_id': 'helper', 'task': 'Order a desk.'}, OneMember(), None)
        self.assertEqual(refused, [])
        self.assertTrue(why.startswith('The member "helper" runs on another service, where these hooks cannot record what it does.'))

    def test_a_hand_over_described_to_the_hook_is_recorded_under_its_description(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                member = Agent(name='Helper', id='helper', telemetry=False, tools=make_tools(world),
                               model=ScriptedModel(script=[call('send_message', NOTE), DONE]))
                asked = {'member_id': 'helper', 'task': 'Tell Sam.'}
                team = Team(name='Office', members=[member], telemetry=False,
                            model=ScriptedModel(script=[call('delegate_task_to_member', asked), DONE]),
                            tool_hooks=ProvaredToolHook(world.writer, {**TOOLS, 'delegate_task_to_member': MESSAGE}).hooks)
                result = self.run_team(team, asynchronous)
                self.assertFalse(any(failed for _, failed in answers(result)))
                [stub] = stubs(world)
                self.assertEqual((stub['action'], stub['details']), (MESSAGE, [{'name': 'provared.arguments', 'sha256': arguments_fingerprint(asked)}]))
                # The member, which carries no hooks, acted unrecorded: the developer described the hand-over instead.
                self.assertEqual(world.messages, [NOTE])

    def test_a_member_whose_hooks_let_its_undescribed_tools_run_counts_as_unrecorded(self):
        # Unless the team's own hook lets such tools run unrecorded too.
        for leader in ('refuse', 'run'):
            with self.subTest(leader=leader):
                world = World()
                member = Agent(name='Helper', id='helper', telemetry=False, tools=make_tools(world),
                               model=ScriptedModel(script=[call('send_message', NOTE), DONE]),
                               tool_hooks=ProvaredToolHook(world.writer, {}, unlisted='run').hooks)
                team = Team(name='Office', members=[member], telemetry=False,
                            model=ScriptedModel(script=[call('delegate_task_to_member', {'member_id': 'helper', 'task': 'Tell Sam.'}), DONE]),
                            tool_hooks=ProvaredToolHook(world.writer, TOOLS, unlisted=leader).hooks)
                if leader == 'refuse':
                    with self.assertWarns(RuntimeWarning):
                        result = self.run_team(team, False)
                    self.assertIn('carries no tool hooks of this stub writer that record each of its tool calls', answers(result)[0][0])
                    self.assertEqual(world.messages, [])
                else:
                    self.run_team(team, False)
                    self.assertEqual(world.messages, [NOTE])
                self.assertEqual(stubs(world), [])

    def task_mode_team(self, world, member, script, tools=TOOLS):
        from agno.team.mode import TeamMode

        return Team(name='Office', members=[member], telemetry=False, mode=TeamMode.tasks,
                    model=ScriptedModel(script=script), tool_hooks=ProvaredToolHook(world.writer, tools).hooks)

    def test_a_team_in_task_mode_hands_a_task_only_to_a_member_whose_work_is_recorded(self):
        new_task = call('create_task', {'title': 'Note', 'description': 'Tell Sam the paper is ordered.', 'assignee': 'helper'})
        for hand_over in ('execute_task', 'execute_tasks_parallel'):
            for hooked in (True, False):
                for asynchronous in (False, True):
                    with self.subTest(hand_over=hand_over, hooked=hooked, asynchronous=asynchronous):
                        world = World()
                        member = Agent(name='Helper', id='helper', telemetry=False, tools=make_tools(world),
                                       model=ScriptedModel(script=[call('send_message', NOTE), DONE]),
                                       tool_hooks=ProvaredToolHook(world.writer, TOOLS).hooks if hooked else None)
                        team = self.task_mode_team(world, member, [new_task, hand_the_task_over(hand_over), DONE, DONE, DONE])
                        if hooked:
                            result = self.run_team(team, asynchronous)
                            self.assertFalse(any(failed for _, failed in answers(result)))
                            # The list of tasks and the hand-over leave no stub; what the member did does.
                            self.assertEqual((world.messages, [s['action'] for s in stubs(world)]), ([NOTE], [MESSAGE]))
                            continue
                        with self.assertWarns(RuntimeWarning):
                            result = self.run_team(team, asynchronous)
                        told = answers(result)
                        self.assertEqual(told[0][1], False)
                        self.assertTrue(told[1][1])
                        self.assertIn(f'The tool "{hand_over}" was not run. The member "helper" carries no tool hooks', told[1][0])
                        self.assertEqual((world.messages, stubs(world)), ([], []))

    def test_a_hand_over_of_tasks_goes_by_agno_s_own_list_not_the_copy_in_the_session_state(self):
        # The model may rewrite the copy of the list of tasks that the session
        # state holds (update_session_state); Agno hands each task to the member
        # that its own list names, and so does the check.
        from agno.team.mode import TeamMode
        from agno.team.task import TASK_LIST_KEY

        new_task = call('create_task', {'title': 'Note', 'description': 'Tell Sam the paper is ordered.', 'assignee': 'helper'})

        def disguise(messages):
            made = [m.content for m in messages if getattr(m, 'role', None) == 'tool' and isinstance(m.content, str) and 'Task created' in m.content]
            task_id = re.search(r'\[([0-9a-f]+)\]', made[-1]).group(1)
            told = {'tasks': [{'id': task_id, 'title': 'Note', 'assignee': 'recorded', 'status': 'pending'}]}
            return call('update_session_state', {'session_state_updates': {TASK_LIST_KEY: told}})

        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                recorded = Agent(name='Recorded', id='recorded', telemetry=False, tools=make_tools(world),
                                 model=ScriptedModel(script=[DONE]), tool_hooks=ProvaredToolHook(world.writer, TOOLS).hooks)
                loose = Agent(name='Helper', id='helper', telemetry=False, tools=make_tools(world),
                              model=ScriptedModel(script=[call('send_message', NOTE), DONE]))
                team = Team(name='Office', members=[recorded, loose], telemetry=False, mode=TeamMode.tasks,
                            session_state={}, enable_agentic_state=True,
                            model=ScriptedModel(script=[new_task, disguise, hand_the_task_over('execute_tasks_parallel'), DONE, DONE, DONE]),
                            tool_hooks=ProvaredToolHook(world.writer, TOOLS).hooks)
                with self.assertWarns(RuntimeWarning):
                    result = self.run_team(team, asynchronous)
                told = answers(result)
                self.assertEqual([failed for _, failed in told], [False, False, True])
                self.assertIn('The tool "execute_tasks_parallel" was not run. The member "helper" carries no tool hooks', told[2][0])
                self.assertEqual((world.messages, stubs(world)), ([], []))

    def test_a_task_given_to_another_member_after_the_check_is_checked_again_as_it_starts(self):
        # In an asynchronous run Agno starts each hand-over once every call of
        # the model's reply has been through the hooks. Here execute_task,
        # described to the hook, gives the task to a member whose work is not
        # recorded, and starts first; execute_tasks_parallel went through the
        # hooks while the task was still the recorded member's.
        from agno.team.mode import TeamMode

        class Slow(ScriptedModel):
            async def ainvoke(self, *args, **kwargs):
                await asyncio.sleep(0.3)  # a member that takes a moment to answer
                return self._next(kwargs.get('messages'))

        new_task = call('create_task', {'title': 'Note', 'description': 'Tell Sam the paper is ordered.', 'assignee': 'recorded'})

        def both(messages):
            made = [m.content for m in messages if getattr(m, 'role', None) == 'tool' and isinstance(m.content, str) and 'Task created' in m.content]
            task_id = re.search(r'\[([0-9a-f]+)\]', made[-1]).group(1)
            return calls(('execute_task', {'task_id': task_id, 'member_id': 'helper'}), ('execute_tasks_parallel', {'task_ids': [task_id]}))

        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                recorded = Agent(name='Recorded', id='recorded', telemetry=False, tools=make_tools(world),
                                 model=ScriptedModel(script=[DONE]), tool_hooks=ProvaredToolHook(world.writer, TOOLS).hooks)
                loose = Agent(name='Helper', id='helper', telemetry=False, tools=make_tools(world), model=Slow(script=[DONE, DONE]))
                team = Team(name='Office', members=[recorded, loose], telemetry=False, mode=TeamMode.tasks,
                            model=ScriptedModel(script=[new_task, both, DONE, DONE, DONE]),
                            tool_hooks=ProvaredToolHook(world.writer, {**TOOLS, 'execute_task': MESSAGE}).hooks)
                with self.assertWarns(RuntimeWarning):
                    result = self.run_team(team, asynchronous)
                told = answers(result)
                self.assertEqual([failed for _, failed in told], [False, False, True])
                self.assertIn('The tool "execute_tasks_parallel" was not run. The member "helper" carries no tool hooks', told[2][0])
                # The member whose work is not recorded ran once, handed the task by
                # the recorded execute_task; the recorded member never ran.
                self.assertEqual((len(loose.model.script), len(recorded.model.script)), (1, 1))
                self.assertEqual([s['action'] for s in stubs(world)], [MESSAGE])

    def test_task_mode_steps_described_to_the_hook_are_recorded_under_their_description(self):
        world = World()
        member = Agent(name='Helper', id='helper', telemetry=False, tools=make_tools(world),
                       model=ScriptedModel(script=[call('send_message', NOTE), DONE]))
        new_task = call('create_task', {'title': 'Note', 'description': 'Tell Sam the paper is ordered.', 'assignee': 'helper'})
        team = self.task_mode_team(world, member, [new_task, hand_the_task_over('execute_task'), DONE, DONE, DONE],
                                   tools={**TOOLS, 'create_task': MESSAGE, 'execute_task': MESSAGE})
        result = self.run_team(team, False)
        self.assertFalse(any(failed for _, failed in answers(result)))
        self.assertEqual(([s['action'] for s in stubs(world)], world.messages), ([MESSAGE, MESSAGE], [NOTE]))

    def test_a_stub_does_not_hold_the_session_state_that_a_tool_reads(self):
        # A stated limit: the session state passes unrecorded, so a tool that
        # acts on it has a stub that does not hold what it acted on.
        from agno.run import RunContext

        world = World()

        def checkout(run_context: RunContext) -> str:
            """Order everything in the cart."""
            cart = run_context.session_state.get('cart', [])
            world.orders.extend(cart)
            return f'Ordered {len(cart)} items.'

        hook = ProvaredToolHook(world.writer, {'checkout': {'action': ORDER, 'with': SUPPLIER, 'amount': {'unit': 'GBP', 'value': 1}}})
        agent = make_agent(world, [call('update_session_state', {'session_state_updates': {'cart': ['desk', 'chair']}}), call('checkout', {}), DONE],
                           hook, tools=[checkout], session_state={}, enable_agentic_state=True)
        self.run_agent(world, None, None, agent=agent)
        [stub] = stubs(world)
        self.assertEqual((world.orders, stub['details']), (['desk', 'chair'], [{'name': 'provared.arguments', 'sha256': arguments_fingerprint({})}]))

    def test_a_team_s_own_tools_are_recorded_by_the_team_s_hooks(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                member = Agent(name='Helper', model=ScriptedModel(script=[DONE]), telemetry=False)
                team = Team(name='Office', members=[member], tools=make_tools(world), telemetry=False,
                            model=ScriptedModel(script=[call('order_supplies', PAPER), call('order_supplies', DESK), DONE]),
                            tool_hooks=ProvaredToolHook(world.writer, TOOLS).hooks)
                refused.clear()
                with offline():
                    asyncio.run(team.arun(QUESTION)) if asynchronous else team.run(QUESTION)
                self.assertEqual(refused, [])
                self.assertEqual((world.orders, len(stubs(world))), ([PAPER], 1))

    def test_agno_s_own_session_state_tool_runs_unrecorded(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                agent = make_agent(world, [call('update_session_state', {'session_state_updates': {'paper': 'ordered'}}), DONE],
                                   ProvaredToolHook(world.writer, TOOLS), session_state={}, enable_agentic_state=True)
                result = self.run_agent(world, None, None, agent=agent, asynchronous=asynchronous)
                self.assertEqual([failed for _, failed in answers(result)], [False])
                self.assertEqual(result.session_state.get('paper'), 'ordered')
                self.assertEqual(stubs(world), [])

    def test_a_tool_of_another_origin_with_the_name_of_one_of_agno_s_own_is_not_passed(self):
        world = World()
        changed = []

        def update_session_state(session_state_updates: dict) -> str:
            """Not Agno's own."""
            changed.append(session_state_updates)
            return 'changed'

        with self.assertWarns(RuntimeWarning):
            result = self.run_agent(world, [call('update_session_state', {'session_state_updates': {'k': 'v'}}), DONE],
                                    ProvaredToolHook(world.writer, TOOLS), tools=[update_session_state])
        self.assertEqual(answers(result), [('The tool "update_session_state" was not run. Provared records no tool of that name.', True)])
        self.assertEqual(changed, [])


class AgnosControlOfTheRun(Runs, unittest.TestCase):
    def test_a_tool_that_acts_then_asks_agno_to_retry_or_stop_leaves_a_stub(self):
        for raised in (RetryAgentRun, StopAgentRun):
            for asynchronous in (False, True):
                with self.subTest(raised=raised.__name__, asynchronous=asynchronous):
                    world = World()

                    def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
                        """Order office supplies."""
                        world.orders.append(item)
                        raise raised(f'Ordered {item}. Order two more items.')

                    result = self.run_agent(world, [call('order_supplies', PAPER), 'The model answered again.', DONE],
                                            ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies], asynchronous=asynchronous)
                    self.assertEqual((world.orders, [s['action'] for s in stubs(world)]), (['printer paper'], [ORDER]))
                    # And Agno is still handed the exception: it tells the model, and goes on or stops as asked.
                    self.assertEqual(answers(result), [('Ordered printer paper. Order two more items.', True)])
                    self.assertEqual(result.content, 'The model answered again.' if raised is RetryAgentRun else '')

    def test_a_tool_that_cancels_itself_cancels_the_run_as_it_would_without_the_hooks(self):
        world = World()

        async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            self.run_agent(world, [call('order_supplies', PAPER), DONE, DONE], ProvaredToolHook(world.writer, TOOLS),
                           tools=[order_supplies], asynchronous=True)
        self.assertEqual(stubs(world), [])

    def test_a_failure_in_the_writer_s_thread_reaches_the_model_and_does_not_hang(self):
        class Halt(BaseException):
            pass

        def amount(args):
            raise Halt()

        world = World()
        result = in_time(self, lambda: self.run_agent(world, [call('order_supplies', PAPER), DONE],
                                                      ProvaredToolHook(world.writer, {'order_supplies': {'action': ORDER, 'amount': amount}}),
                                                      asynchronous=True), 30)
        self.assertEqual(answers(result), [('The stub writer stopped with Halt.', True)])
        self.assertEqual((world.orders, stubs(world)), ([], []))


def changing(function_name, function, arguments):
    """A hook that changes each call's total to 250 GBP, as a person
    reviewing the call might, and passes the changed call on."""
    return function(**{**arguments, 'total_gbp': 250})


def in_place(function_name, function, arguments):
    """The same change, made as Agno's own documentation shows it: in place."""
    arguments['total_gbp'] = 250
    return function(**arguments)


def answers_itself(function_name, function, arguments):
    """A hook that answers in the tool's place."""
    return 'Ordered (from a cache).'


def made_as_agno_makes_it(world, ours, hooks_of_the_call, hooks_of_the_agent, asynchronous):
    """A call of order_supplies, made as Agno makes one, with the hooks given."""
    agent = make_agent(world, [], hooks_of_the_agent)
    function = Function.from_callable(make_tools(world)[0])
    function.tool_hooks = hooks_of_the_call
    function._agent = agent
    function.process_entrypoint()
    fc = FunctionCall(function=function, arguments=dict(PAPER))
    return asyncio.run(fc.aexecute()) if asynchronous else fc.execute()


def chained_as_agno_chains_it(world, ours, chain, asynchronous):
    """A call of order_supplies through Agno's own chain of hooks, built from
    "chain", while the call's list of hooks and the agent's show only the
    hook's two parts."""
    agent = make_agent(world, [], ours)
    function = Function.from_callable(make_tools(world)[0])
    function.tool_hooks = chain
    function._agent = agent
    function.process_entrypoint()
    fc = FunctionCall(function=function, arguments=dict(PAPER))

    async def asynchronously():
        built = await fc._build_nested_execution_chain_async({})
        function.tool_hooks = list(ours.hooks)
        return await built(function.name, function.entrypoint, fc.arguments)

    if asynchronous:
        return asyncio.run(asynchronously())
    built = fc._build_nested_execution_chain({})
    function.tool_hooks = list(ours.hooks)
    return built(function.name, function.entrypoint, fc.arguments)


class WhereItStands(Runs, unittest.TestCase):
    """Agno hands the tool the call's own arguments, not those a hook passes
    on, and a hook may answer in the tool's place; so the hooks must be the
    hook's own two parts, and no other."""

    def test_with_another_hook_before_or_after_it_no_tool_is_run(self):
        for other in (changing, in_place):
            for first in (True, False):
                for asynchronous in (False, True):
                    with self.subTest(other=other.__name__, provared_first=first, asynchronous=asynchronous):
                        world = World()
                        ours = ProvaredToolHook(world.writer, TOOLS)
                        with self.assertWarns(RuntimeWarning):
                            result = self.run_agent(world, [call('order_supplies', PAPER), DONE],
                                                    [*ours.hooks, other] if first else [other, *ours.hooks], asynchronous=asynchronous)
                        [(told, failed)] = answers(result)
                        self.assertTrue(failed)
                        self.assertIn('must be given as the only tool hooks', told)
                        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_given_in_any_other_way_it_runs_nothing(self):
        for asynchronous in (False, True):
            world = World()
            ours = ProvaredToolHook(world.writer, TOOLS)
            for hooks, why in (([ours], 'the hook alone'), (list(reversed(ours.hooks)), 'its parts the wrong way round'),
                               ([ours, ProvaredToolHook(world.writer, TOOLS).hooks[1]], 'another hook\'s second part')):
                with self.subTest(why, asynchronous=asynchronous), self.assertWarns(RuntimeWarning):
                    result = self.run_agent(world, [call('order_supplies', PAPER), DONE], hooks, asynchronous=asynchronous)
                    self.assertIn('must be given as the only tool hooks', answers(result)[0][0])
                    self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_on_a_tool_alone_it_runs_nothing(self):
        # A hook set on one tool alone would leave the agent's other tools unrecorded.
        world = World()
        ours = ProvaredToolHook(world.writer, TOOLS)
        order_supplies = tool(name='order_supplies', tool_hooks=list(ours.hooks))(make_tools(world)[0])
        agent = Agent(model=ScriptedModel(script=[call('order_supplies', PAPER), DONE]), tools=[order_supplies], telemetry=False)
        with self.assertWarns(RuntimeWarning):
            result = self.run_agent(world, None, None, agent=agent)
        self.assertIn('must be given as the only tool hooks', answers(result)[0][0])
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_hook_that_agno_puts_after_its_parts_stops_the_call(self):
        # Agno 3.1 uses the agent's hooks in place of a tool's own. A change
        # proposed to Agno would add a tool's own hooks after the agent's.
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                ours = ProvaredToolHook(world.writer, TOOLS)
                with self.assertWarns(RuntimeWarning):
                    outcome = made_as_agno_makes_it(world, ours, [*ours.hooks, changing], ours, asynchronous)
                self.assertEqual(outcome.status, 'failure')
                self.assertIn('must be given as the only tool hooks', outcome.error)
                self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_hook_between_its_parts_that_answers_in_the_tool_s_place_stops_the_call(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                ours = ProvaredToolHook(world.writer, TOOLS)
                with self.assertWarns(RuntimeWarning):
                    outcome = made_as_agno_makes_it(world, ours, [ours.hooks[0], answers_itself, ours.hooks[1]], ours, asynchronous)
                self.assertEqual(outcome.status, 'failure')
                self.assertIn('must be given as the only tool hooks', outcome.error)
                self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_where_the_chain_holds_a_hook_its_list_does_not_show_the_call_is_stopped(self):
        # As a later Agno might build its chain: the list of hooks shows only
        # the two parts, and the chain holds another hook between them, or
        # after them. Each part looks at what follows it in the chain.
        for where in ('between', 'after'):
            for asynchronous in (False, True):
                with self.subTest(where=where, asynchronous=asynchronous):
                    world = World()
                    ours = ProvaredToolHook(world.writer, TOOLS)
                    chain = [ours.hooks[0], answers_itself, ours.hooks[1]] if where == 'between' else [*ours.hooks, changing]
                    with self.assertWarns(RuntimeWarning), self.assertRaises(Exception) as raised:
                        chained_as_agno_chains_it(world, ours, chain, asynchronous)
                    self.assertIn('must be given as the only tool hooks', str(raised.exception))
                    self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_the_agent_s_hooks_must_be_its_parts_as_well_as_the_call_s(self):
        world = World()
        ours = ProvaredToolHook(world.writer, TOOLS)
        with self.assertWarns(RuntimeWarning):
            outcome = made_as_agno_makes_it(world, ours, list(ours.hooks), [ours, changing], False)
        self.assertEqual(outcome.status, 'failure')
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_the_call_s_own_hooks_must_be_its_parts_also_where_agno_skips_the_second(self):
        # An ordinary run inside an event loop, where Agno skips the second
        # part: the call's own list must still hold both parts.
        world = World()
        ours = ProvaredToolHook(world.writer, TOOLS)

        async def inside_an_event_loop():
            return made_as_agno_makes_it(world, ours, [ours.hooks[0]], ours, False)

        with self.assertWarns(RuntimeWarning):
            outcome = asyncio.run(inside_an_event_loop())
        self.assertEqual(outcome.status, 'failure')
        self.assertIn('must be given as the only tool hooks', outcome.error)
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_call_it_cannot_read_is_not_run(self):
        # As where a later Agno built its chain of hooks in another way.
        world = World()
        ours = ProvaredToolHook(world.writer, TOOLS)
        agent = make_agent(world, [], ours)
        ran = []
        with self.assertWarns(RuntimeWarning), self.assertRaises(Exception) as raised:
            ours(function_name='order_supplies', function=lambda **args: ran.append(args), arguments=dict(PAPER), agent=agent)
        self.assertIn('cannot read', str(raised.exception))
        self.assertEqual((ran, stubs(world)), ([], []))

    def test_a_change_made_before_the_hooks_is_the_call_checked(self):
        # A tool's pre_hook runs before the tool hooks, and may change the call.
        def raise_the_total(fc):
            fc.arguments['total_gbp'] = 250

        world = World()
        order_supplies = tool(name='order_supplies', pre_hook=raise_the_total)(make_tools(world)[0])
        result = self.run_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies])
        self.assertTrue(answers(result)[0][0].startswith('The tool "order_supplies" was not run. With this action the total would be 250 GBP.'))
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_generator_tool_is_not_run(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()
                ran = []

                def order_supplies(item: str, quantity: int, total_gbp: int):
                    """Order office supplies."""
                    ran.append(item)
                    yield 'ordered'

                async def send_message(to: str, text: str):
                    """Send a short message."""
                    ran.append(to)
                    yield 'sent'

                tools = [order_supplies, send_message] if asynchronous else [order_supplies]
                script = calls(('order_supplies', PAPER), ('send_message', NOTE)) if asynchronous else call('order_supplies', PAPER)
                result = self.run_agent(world, [script, DONE], ProvaredToolHook(world.writer, TOOLS), tools=tools, asynchronous=asynchronous)
                self.assertEqual(len(answers(result)), len(tools))
                for told, failed in answers(result):
                    self.assertTrue(failed)
                    self.assertIn('is a generator function', told)
                self.assertEqual((ran, stubs(world)), ([], []))

    def test_a_call_that_agno_answers_from_its_cache_still_gets_a_stub(self):
        # A stated limit: Agno answers such a call without running the tool.
        world = World()
        with tempfile.TemporaryDirectory() as kept:
            send_message = tool(name='send_message', cache_results=True, cache_dir=kept)(make_tools(world)[1])
            ours = ProvaredToolHook(world.writer, TOOLS)
            for _ in range(2):
                self.run_agent(world, [call('send_message', NOTE), DONE], ours, tools=[send_message])
        self.assertEqual((world.messages, len(stubs(world))), ([NOTE], 2))

    def test_a_copy_of_the_agent_shares_the_hooks_and_their_writer(self):
        # Given as the README says, and as a list, which Agno copies item by item.
        for given in (lambda ours: ours, lambda ours: list(ours.hooks)):
            world = World()
            ours = ProvaredToolHook(world.writer, TOOLS)
            agent = make_agent(world, [call('order_supplies', PAPER), DONE], given(ours)).deep_copy()
            self.assertEqual([id(h) for h in agent.tool_hooks], [id(h) for h in ours.hooks])
            self.run_agent(world, None, None, agent=agent)
            self.assertEqual((world.orders, len(stubs(world))), ([PAPER], 1))
        self.assertEqual([id(h) for h in copy.deepcopy(list(ours.hooks))], [id(h) for h in ours.hooks])
        self.assertEqual([id(h) for h in copy.copy(ours.hooks)], [id(h) for h in ours.hooks])


class Asynchronous(Runs, unittest.TestCase):
    def test_the_second_part_is_asynchronous_only_where_an_event_loop_runs(self):
        # So that Agno skips it in no ordinary run, and in an asynchronous
        # run takes every call through its asynchronous path. Python 3.11
        # cannot mark it so only on the event loop, so there it is always
        # asynchronous, as the README says.
        last = ProvaredToolHook(World().writer, TOOLS).hooks[1]
        self.assertEqual(inspect.iscoroutinefunction(last), sys.version_info < (3, 12))

        async def on_the_loop():
            return inspect.iscoroutinefunction(last)

        self.assertTrue(asyncio.run(on_the_loop()))

    def test_an_ordinary_tool_runs_in_a_thread_not_on_the_event_loop(self):
        world = World()
        loops = []

        def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            try:
                loops.append(asyncio.get_running_loop())
            except RuntimeError:
                loops.append(None)
            return 'ordered'

        self.run_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS),
                       tools=[order_supplies], asynchronous=True)
        self.assertEqual((loops, len(stubs(world))), ([None], 1))

    def test_many_calls_at_once_all_finish_with_ordinary_and_asynchronous_tools(self):
        # Without the second part, Agno runs each ordinary call in one of the
        # event loop's shared threads, where it would wait for the writer;
        # an asynchronous tool that needs such a thread would wait for ever.
        found = in_a_process_of_its_own(self, 'many-calls', 120)
        self.assertEqual(found, {'refused': [], 'messages': 60, 'orders': 6, 'stubs': 66, 'stubs of each agent': [1] * 20})

    def test_reading_the_writer_while_tools_wait_does_not_hang(self):
        # Read from the event loop's shared threads, the reads would take
        # every one, and the waiting tool, which needs one, would wait for ever.
        found = in_a_process_of_its_own(self, 'reads', 60)
        self.assertEqual(found, {'refused': [], 'reads': SHARED_THREADS * 2, 'orders': ['printer paper'], 'messages': [NOTE],
                                 'stubs': 2, 'last read': 'the writer\'s snapshot'})

    def test_an_ordinary_run_from_inside_an_event_loop_is_recorded(self):
        # As in a notebook: Agno then skips the second part, and the hook still records.
        world = World()
        agent = make_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS))

        async def ordinary_run():
            return agent.run(QUESTION)

        refused.clear()
        with offline():
            asyncio.run(ordinary_run())
        self.assertEqual(refused, [])
        self.assertEqual((world.orders, len(stubs(world))), ([PAPER], 1))

    def test_cancelling_a_run_cancels_the_tool_and_frees_the_writer(self):
        world = World()

        async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            await asyncio.sleep(30)
            world.orders.append(item)
            return 'ordered'

        agent = make_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies])

        async def cancelled():
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(agent.arun(QUESTION), 1)
            # While the event loop goes on, as in a server, the writer is free again.
            hook = agent.tool_hooks[0]
            await asyncio.wait_for(hook.snapshot(), 5)

        with offline():
            in_time(self, lambda: asyncio.run(cancelled()), 30)
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_run_cancelled_before_its_tool_starts_never_runs_it(self):
        world = World()

        async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            world.orders.append(item)
            return 'ordered'

        def slow_amount(args):
            time.sleep(1)
            return {'unit': 'GBP', 'value': args['total_gbp']}

        hook = ProvaredToolHook(world.writer, {'order_supplies': {'action': ORDER, 'with': SUPPLIER, 'amount': slow_amount}})
        agent = make_agent(world, [call('order_supplies', PAPER), DONE], hook, tools=[order_supplies])

        async def cancelled():
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(agent.arun(QUESTION), 0.3)
            await asyncio.sleep(1.5)  # the writer has finished its check meanwhile
            return await hook.snapshot()

        with offline():
            in_time(self, lambda: asyncio.run(cancelled()), 30)
        self.assertEqual((world.orders, stubs(world)), ([], []))

    def test_a_cancelled_run_holds_the_writer_until_its_ordinary_tool_ends(self):
        # An ordinary tool cannot be stopped once it runs: the next action
        # waits for it, and its stub is written, since it completed.
        world = World()
        happened = []  # in order, not by the clock, which on Windows can give two moments one time

        def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            time.sleep(1)
            world.orders.append(item)
            happened.append('ordered')
            return 'ordered'

        def send_message(to: str, text: str) -> str:
            """Send a short message."""
            happened.append('sent')
            world.messages.append({'to': to, 'text': text})
            return 'sent'

        hook = ProvaredToolHook(world.writer, TOOLS)
        first = make_agent(world, [call('order_supplies', PAPER), DONE], hook, tools=[order_supplies, send_message])
        second = make_agent(world, [call('send_message', NOTE), DONE], hook, tools=[order_supplies, send_message])

        async def main():
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(first.arun(QUESTION), 0.3)
            await second.arun(QUESTION)

        with offline():
            in_time(self, lambda: asyncio.run(main()), 30)
        self.assertEqual(happened, ['ordered', 'sent'])
        self.assertEqual([s['action'] for s in stubs(world)], [ORDER, MESSAGE])

    def test_the_same_holds_where_the_program_s_event_loop_ends_at_once(self):
        # asyncio.run ends by cancelling every task left, a second time.
        world = World()
        happened = []

        def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            happened.append('order starts')
            time.sleep(1)
            world.orders.append(item)
            happened.append('order ends')
            return 'ordered'

        def send_message(to: str, text: str) -> str:
            """Send a short message."""
            happened.append('message sent')
            return 'sent'

        hook = ProvaredToolHook(world.writer, TOOLS)
        first = make_agent(world, [call('order_supplies', PAPER), DONE], hook, tools=[order_supplies, send_message])
        second = make_agent(world, [call('send_message', NOTE), DONE], hook, tools=[order_supplies, send_message])

        def program():
            with self.assertRaises(TimeoutError):
                asyncio.run(asyncio.wait_for(first.arun(QUESTION), 0.3))
            asyncio.run(second.arun(QUESTION))

        with offline():
            in_time(self, program, 30)
        self.assertEqual(happened, ['order starts', 'order ends', 'message sent'])
        self.assertEqual([s['action'] for s in stubs(world)], [ORDER, MESSAGE])

    def test_where_the_program_closes_its_event_loop_while_a_tool_runs_the_writer_is_not_held_for_ever(self):
        # The ordinary tool goes on to its end: its stub is written, and the writer is freed.
        found = in_a_process_of_its_own(self, 'loop-closed', 60)
        self.assertEqual(found, {'refused': [], 'happened': ['timed out', 'event loop closed', 'ordered', 'the writer answered'],
                                 'orders': ['printer paper'], 'stubs': [ORDER], 'same book': True})

    def test_where_the_program_closes_its_event_loop_with_the_run_under_way_the_writer_is_not_held_for_ever(self):
        # Nothing cancels the run. An ordinary tool goes on to its end and gets its stub.
        found = in_a_process_of_its_own(self, 'loop-closed-under-way', 60)
        self.assertEqual(found, {'refused': [], 'happened': ['left under way', 'event loop closed', 'ordered', 'the writer answered'],
                                 'orders': ['printer paper'], 'stubs': [ORDER], 'same book': True})
        # An asynchronous tool cannot go on without its event loop: it did not complete, no stub is written.
        found = in_a_process_of_its_own(self, 'loop-closed-under-way-asynchronous', 60)
        self.assertEqual(found, {'refused': [], 'happened': ['left under way', 'event loop closed', 'the writer answered'],
                                 'orders': [], 'stubs': [], 'same book': True})

    def test_an_asynchronous_tool_that_ended_as_the_event_loop_stopped_gets_its_stub(self):
        found = in_a_process_of_its_own(self, 'loop-stopped-as-the-tool-ends', 60)
        self.assertEqual(found, {'refused': [], 'happened': ['event loop stopped', 'the writer answered'],
                                 'orders': ['printer paper'], 'stubs': [ORDER], 'same book': True})

    def test_a_call_made_from_inside_a_tool_is_not_taken_for_the_tool(self):
        # Such a call carries the mark of the call whose tool makes it. Where
        # its own thread, ended, was taken for the tool's, a stub was written
        # once the event loop stopped: for an order never placed, or before
        # the order was placed, with the writer freed while the tool still acted.
        for how in ('helper agent', 'same task'):
            with self.subTest(how=how):
                found = in_a_process_of_its_own(self, f'call-from-inside-the-tool-{how.replace(" ", "-")}', 60)
                self.assertEqual(found, {'refused': [], 'happened': ['left under way', 'event loop closed', 'the writer answered'],
                                         'orders': [], 'stubs': [], 'same book': True})
        with self.subTest(how='ordinary tool'):
            found = in_a_process_of_its_own(self, 'call-from-inside-the-tool-ordinary-tool', 60)
            self.assertEqual(found, {'refused': [], 'happened': ['left under way', 'event loop closed', 'ordered', 'the writer answered'],
                                     'orders': ['printer paper'], 'stubs': [ORDER], 'same book': True})

    def test_a_cancelled_asynchronous_tool_that_completes_all_the_same_holds_the_writer_and_gets_its_stub(self):
        # The event loop goes on, as in a server. The tool catches the
        # cancellation and places its order: the writer waits for it, the
        # next action starts only once it has ended, and its stub is written.
        world = World()
        times = {}
        happened = []  # in order, not by the clock, which on Windows can give two moments one time

        async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
            """Order office supplies."""
            times['started'] = time.monotonic()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                await asyncio.sleep(1)  # it finishes its order all the same
            world.orders.append(item)
            happened.append('ordered')
            return 'ordered'

        def send_message(to: str, text: str) -> str:
            """Send a short message."""
            happened.append('sent')
            world.messages.append({'to': to, 'text': text})
            return 'sent'

        hook = ProvaredToolHook(world.writer, TOOLS)
        first = make_agent(world, [call('order_supplies', PAPER), DONE], hook, tools=[order_supplies, send_message])
        second = make_agent(world, [call('send_message', NOTE), DONE], hook, tools=[order_supplies, send_message])

        async def main():
            run = asyncio.ensure_future(first.arun(QUESTION))
            while 'started' not in times:
                await asyncio.sleep(0.01)
            run.cancel()
            [ended] = await asyncio.gather(run, return_exceptions=True)
            self.assertIsInstance(ended, asyncio.CancelledError)
            await second.arun(QUESTION)
            await asyncio.sleep(1.5)  # time for the order to be placed, whatever the writer did

        with offline():
            in_time(self, lambda: asyncio.run(main()), 30)
        self.assertEqual((world.orders, len(world.messages)), (['printer paper'], 1))
        self.assertEqual(happened, ['ordered', 'sent'])
        self.assertEqual([s['action'] for s in stubs(world)], [ORDER, MESSAGE])

    def test_an_ordinary_tool_needs_none_of_the_event_loop_s_shared_threads(self):
        # Every shared thread is taken while the agent runs, as on a busy server.
        found = in_a_process_of_its_own(self, 'shared-threads-taken', 30)
        self.assertEqual(found, {'refused': [], 'orders': ['printer paper'], 'stubs': 1})

    def test_a_refusal_raised_by_the_tool_itself_is_passed_on(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                world = World()

                def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
                    """Order office supplies."""
                    world.orders.append(item)
                    raise Refusal('bad-field', 'Raised by the tool, after it placed the order.')

                result = self.run_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS),
                                        tools=[order_supplies], asynchronous=asynchronous)
                self.assertEqual(answers(result), [('Raised by the tool, after it placed the order.', True)])
                self.assertEqual((world.orders, stubs(world)), (['printer paper'], []))


def scenario_many_calls():
    """60 ordinary calls and 6 asynchronous ones that need a shared thread,
    asked for in one reply; then 20 agents at once."""
    world = World()

    async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
        """Order office supplies."""
        await asyncio.to_thread(time.sleep, 0.01)
        world.orders.append(item)
        return 'ordered'

    def send_message(to: str, text: str) -> str:
        """Send a short message."""
        time.sleep(0.005)
        world.messages.append({'to': to, 'text': text})
        return 'sent'

    named = []
    for i in range(60):
        named.append(('send_message', {'to': f'Person {i}', 'text': 'Hello.'}))
        if i % 10 == 0:
            named.append(('order_supplies', {'item': f'pens {i}', 'quantity': 1, 'total_gbp': 1}))
    agent = make_agent(world, [calls(*named), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies, send_message])
    worlds = [World() for _ in range(20)]
    agents = [make_agent(w, [call('send_message', NOTE), DONE], ProvaredToolHook(w.writer, TOOLS)) for w in worlds]

    async def all_of_them():
        return await asyncio.gather(*(each.arun(QUESTION) for each in agents))

    refused.clear()
    with offline():
        asyncio.run(agent.arun(QUESTION))
        asyncio.run(all_of_them())
    return {'refused': refused, 'messages': len(world.messages), 'orders': len(world.orders), 'stubs': len(stubs(world)),
            'stubs of each agent': [len(stubs(w)) for w in worlds]}


def scenario_reads():
    """One agent's asynchronous tool holds the writer; another agent's
    asynchronous tool, which needs one of the event loop's shared threads,
    waits for it; the program then reads the writer, twice as many times as
    the event loop has shared threads."""
    world = World()

    async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
        """Order office supplies."""
        await asyncio.sleep(1)
        world.orders.append(item)
        return 'ordered'

    async def send_message(to: str, text: str) -> str:
        """Send a short message."""
        await asyncio.to_thread(world.messages.append, {'to': to, 'text': text})
        return 'sent'

    hook = ProvaredToolHook(world.writer, TOOLS)
    first = make_agent(world, [call('order_supplies', PAPER), DONE], hook, tools=[order_supplies, send_message])
    second = make_agent(world, [call('send_message', NOTE), DONE], hook, tools=[order_supplies, send_message])

    async def main():
        running = [asyncio.ensure_future(first.arun(QUESTION))]
        await asyncio.sleep(0.2)
        running.append(asyncio.ensure_future(second.arun(QUESTION)))
        await asyncio.sleep(0.2)
        reads = [hook.snapshot() for _ in range(SHARED_THREADS * 2)]
        read = (await asyncio.gather(*running, *reads))[2:]
        return read, await hook.snapshot()

    refused.clear()
    with offline():
        read, last = asyncio.run(main())
    return {'refused': refused, 'reads': len(read), 'orders': world.orders, 'messages': world.messages, 'stubs': len(stubs(world)),
            'last read': 'the writer\'s snapshot' if last == world.writer.snapshot() else 'something else'}


def scenario_shared_threads_taken():
    """Every one of the event loop's shared threads waits on something else
    while an agent's ordinary tool is called."""
    world = World()
    agent = make_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS))

    async def main():
        loop = asyncio.get_running_loop()
        gate = threading.Event()
        taken = [loop.run_in_executor(None, gate.wait, 60) for _ in range(SHARED_THREADS)]
        await asyncio.sleep(0.2)
        try:
            await agent.arun(QUESTION)
        finally:
            gate.set()
        await asyncio.gather(*taken)

    refused.clear()
    with offline():
        asyncio.run(main())
    return {'refused': refused, 'orders': [o['item'] for o in world.orders], 'stubs': len(stubs(world))}


def scenario_loop_closed(asynchronous=False, cancelled=True):
    """A program that runs its own event loop gives a run 0.5 seconds
    (cancelling it then, or leaving it under way), closes the loop while the
    run's tool still runs, and then goes on with the writer from ordinary
    code."""
    world = World()
    happened = []

    def ordinary(item: str, quantity: int, total_gbp: int) -> str:
        """Order office supplies."""
        time.sleep(1.5)
        world.orders.append(item)
        happened.append('ordered')
        return 'ordered'

    async def on_the_loop(item: str, quantity: int, total_gbp: int) -> str:
        """Order office supplies."""
        await asyncio.sleep(1.5)
        world.orders.append(item)
        happened.append('ordered')
        return 'ordered'

    order_supplies = on_the_loop if asynchronous else ordinary
    order_supplies.__name__ = 'order_supplies'
    agent = make_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies])
    refused.clear()
    with offline():
        loop = asyncio.new_event_loop()
        if cancelled:
            try:
                loop.run_until_complete(asyncio.wait_for(agent.arun(QUESTION), 0.5))
            except TimeoutError:
                happened.append('timed out')
        else:
            # The event loop stops with the run under way, and nothing cancels it.
            loop.create_task(agent.arun(QUESTION))
            loop.run_until_complete(asyncio.sleep(0.5))
            happened.append('left under way')
        loop.close()
        happened.append('event loop closed')
        book, _ = world.writer.snapshot()  # waits for an ordinary tool, and then answers
        happened.append('the writer answered')
    return {'refused': refused, 'happened': happened, 'orders': list(world.orders),
            'stubs': [s['action'] for s in stubs(world)], 'same book': book == world.writer.book()}


def scenario_loop_stopped_as_the_tool_ends():
    """An asynchronous tool ends just as the event loop stops, before the
    event loop can pass on that it has ended; the program then closes the
    loop and goes on with the writer from ordinary code."""
    world = World()
    happened = []

    async def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
        """Order office supplies."""
        world.orders.append(item)
        asyncio.get_running_loop().stop()  # the event loop stops once this step is done
        return 'ordered'

    agent = make_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies])
    refused.clear()
    with offline():
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(agent.arun(QUESTION))
        except RuntimeError:
            happened.append('event loop stopped')
        loop.close()
        book, _ = world.writer.snapshot()
        happened.append('the writer answered')
    return {'refused': refused, 'happened': happened, 'orders': list(world.orders),
            'stubs': [s['action'] for s in stubs(world)], 'same book': book == world.writer.book()}


def scenario_call_from_inside_the_tool(how):
    """A recorded tool makes a call of its own, which passes unrecorded
    through the hooks of another stub writer, in a thread of its own: in a
    helper agent's run ("helper agent"), in Agno's call awaited in the tool's
    own task ("same task"), or, from an ordinary tool, in a helper agent's
    run on an event loop of its own ("ordinary tool"). The tool then waits;
    the program's event loop stops with the run under way, and is closed."""
    world, other = World(), World()
    happened = []
    ready = threading.Event()
    helper = Agent(model=ScriptedModel(script=[call('update_session_state', {'session_state_updates': {'note': 'paper'}}), DONE]),
                   tools=[], session_state={}, enable_agentic_state=True, telemetry=False,
                   tool_hooks=ProvaredToolHook(other.writer, TOOLS).hooks)

    def note(text: str) -> str:
        """Make a note."""
        return 'noted'

    async def on_the_loop(item: str, quantity: int, total_gbp: int) -> str:
        """Order office supplies."""
        if how == 'helper agent':
            await helper.arun(QUESTION)
        else:
            passes = ProvaredToolHook(other.writer, {}, unlisted='run')
            function = Function.from_callable(note)
            function.tool_hooks = list(passes.hooks)
            function._agent = make_agent(other, [], passes)
            function.process_entrypoint()
            await FunctionCall(function=function, arguments={'text': 'paper'}).aexecute()
        ready.set()
        await asyncio.sleep(30)
        world.orders.append(item)
        return 'ordered'

    def ordinary(item: str, quantity: int, total_gbp: int) -> str:
        """Order office supplies."""
        asyncio.run(helper.arun(QUESTION))
        ready.set()
        time.sleep(1.5)
        world.orders.append(item)
        happened.append('ordered')
        return 'ordered'

    order_supplies = ordinary if how == 'ordinary tool' else on_the_loop
    order_supplies.__name__ = 'order_supplies'
    agent = make_agent(world, [call('order_supplies', PAPER), DONE], ProvaredToolHook(world.writer, TOOLS), tools=[order_supplies])
    refused.clear()
    with offline():
        loop = asyncio.new_event_loop()
        loop.create_task(agent.arun(QUESTION))
        while not ready.is_set():  # until the call made from inside the tool has ended
            loop.run_until_complete(asyncio.sleep(0.05))
        happened.append('left under way')
        loop.close()
        happened.append('event loop closed')
        book, _ = world.writer.snapshot()
        happened.append('the writer answered')
    return {'refused': refused, 'happened': happened, 'orders': list(world.orders),
            'stubs': [s['action'] for s in stubs(world)], 'same book': book == world.writer.book()}


SCENARIOS = {'many-calls': scenario_many_calls, 'reads': scenario_reads, 'shared-threads-taken': scenario_shared_threads_taken,
             'loop-closed': scenario_loop_closed,
             'loop-closed-under-way': lambda: scenario_loop_closed(cancelled=False),
             'loop-closed-under-way-asynchronous': lambda: scenario_loop_closed(asynchronous=True, cancelled=False),
             'loop-stopped-as-the-tool-ends': scenario_loop_stopped_as_the_tool_ends,
             'call-from-inside-the-tool-helper-agent': lambda: scenario_call_from_inside_the_tool('helper agent'),
             'call-from-inside-the-tool-same-task': lambda: scenario_call_from_inside_the_tool('same task'),
             'call-from-inside-the-tool-ordinary-tool': lambda: scenario_call_from_inside_the_tool('ordinary tool')}


def in_a_process_of_its_own(test, name, seconds):
    """Runs a scenario in a process of its own, and fails the test if it has
    not ended in time. A scenario that waits for ever then fails its test,
    and does not keep the other tests, or the program, from ending."""
    try:
        done = subprocess.run([sys.executable, os.path.abspath(__file__), name], capture_output=True, text=True, timeout=seconds)
    except subprocess.TimeoutExpired:
        test.fail(f'the scenario "{name}" was still running after {seconds} seconds')
    test.assertEqual(done.returncode, 0, done.stderr[-3000:])
    return json.loads(done.stdout.strip().splitlines()[-1])


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in SCENARIOS:
        print(json.dumps(SCENARIOS[sys.argv[1]]()), flush=True)
        os._exit(0)
    unittest.main()
