# The examples, run and checked: for each agent framework, the allowed call
# ran once, the call over the limit did not run and the agent was told why,
# the book checks as intact with exactly one stub, and the framework
# described each recorded tool to its model exactly as it describes the
# plain function (name, parameters, types and description).
#
# Run from this folder: python -m unittest test_examples -v

import asyncio
import contextlib
import socket
import subprocess
import sys
import unittest

import langchain_example
import openai_agents_example
import pydantic_ai_example
from langchain_core.tools import tool as langchain_tool

from provared import arguments_fingerprint

from _world import ORDER, SUPPLIER, World, offline, refused

PAPER = {'item': 'printer paper', 'quantity': 5, 'total_gbp': 30}
REFUSED = 'The tool "order_supplies" was not run. With this action the total would be 280 GBP.'
PARAMETERS = {'order_supplies': {'item': 'string', 'quantity': 'integer', 'total_gbp': 'integer'},
              'send_message': {'to': 'string', 'text': 'string'}}
FIRST_LINES = {'order_supplies': 'Order office supplies from the stationery supplier.',
               'send_message': 'Send a short message to a person in the office.'}
# Each parameter's description, from the "Args:" part of the docstring.
ARGS = {'order_supplies': {'item': 'What to order, for example "printer paper".', 'quantity': 'How many to order.',
                           'total_gbp': 'The total price in pounds sterling, a whole number.'},
        'send_message': {'to': "The person's name.", 'text': 'The message.'}}


class Example:
    """What every example must show. Each subclass names its module."""

    module = None
    # Whether the framework reads each parameter's description from the docstring.
    parameter_descriptions = True

    @classmethod
    def setUpClass(cls):
        cls.shown = []
        refused.clear()
        cls.outcome = cls.module.main(show=cls.shown.append)
        cls.refused = list(refused)

    def test_nothing_was_refused_while_it_ran(self):
        # Not even an attempt that the framework caught and set aside.
        self.assertEqual(self.refused, [])

    def parameters(self, description):
        return description.get('parameters') or description['function']['parameters']

    def text(self, description):
        return description.get('description') or description['function']['description']

    def name(self, description):
        return description.get('name') or description['function']['name']

    def test_the_allowed_call_ran_once_and_the_refused_one_did_not(self):
        world = self.outcome['world']
        self.assertEqual(world.orders, [PAPER])
        self.assertEqual(world.messages, [])

    def test_the_agent_was_told_why_the_call_was_not_taken(self):
        told = [line for line in self.shown if 'The agent was told:' in line]
        self.assertEqual(len(told), 2)
        self.assertIn('Ordered 5 x printer paper for 30 GBP.', told[0])
        self.assertIn(REFUSED, told[1].replace('\\"', '"'))

    def test_the_book_is_intact_and_holds_exactly_one_stub(self):
        summary = self.outcome['check']['summary']
        self.assertTrue(summary['intact'])
        self.assertFalse(summary['problemFound'])
        self.assertTrue(summary['withinSlips'])
        self.assertEqual(summary['counts']['stubs'], 1)
        stub = [e for e in self.outcome['check']['entries'] if e['kind'] == 'stub'][0]['content']
        self.assertEqual(stub['action'], ORDER)
        self.assertEqual(stub['amount'], {'unit': 'GBP', 'value': 30})
        self.assertEqual(stub['with'], SUPPLIER)
        self.assertEqual(stub['details'], [{'name': 'arguments', 'sha256': arguments_fingerprint(PAPER)}])
        self.assertIn('The book checks as intact: yes. The agent stayed within its slip: yes. Stubs in the book: 1.', self.shown)

    def test_each_recorded_tool_is_described_as_the_plain_function_is(self):
        described = self.outcome['described']
        self.assertEqual(sorted(described), ['order_supplies', 'send_message'])
        for name, plain in self.outcome['plain'].items():
            with self.subTest(name):
                d = described[name]
                # What reached the model, against what the framework makes of the plain function.
                self.assertEqual(d, self.module.describe(plain))
                self.assertEqual(self.name(d), name)
                properties = self.parameters(d)['properties']
                self.assertEqual({p: v['type'] for p, v in properties.items()}, PARAMETERS[name])
                self.assertEqual(self.parameters(d)['required'], list(PARAMETERS[name]))
                self.assertTrue(self.text(d).startswith(FIRST_LINES[name]))
                if self.parameter_descriptions:
                    self.assertEqual({p: v['description'] for p, v in properties.items()}, ARGS[name])
                else:
                    self.assertEqual([v for v in properties.values() if 'description' in v], [])


class LangChain(Example, unittest.TestCase):
    module = langchain_example
    # LangChain's agent turns a function into a tool without reading the
    # parameters' descriptions from its docstring: the whole docstring is
    # the tool's description, for the plain function and the recorded one alike.
    parameter_descriptions = False

    def test_the_tool_s_arguments_schema_is_the_plain_function_s(self):
        world = World()
        plain = langchain_example.make_tools(world)
        for recorded in langchain_example.record(world, plain):
            t, p = langchain_tool(recorded), langchain_tool(plain[recorded.__name__])
            self.assertEqual(t.name, p.name)
            self.assertEqual(t.description, p.description)
            self.assertEqual(t.args_schema.model_json_schema(), p.args_schema.model_json_schema())

    def test_the_refusal_went_back_to_the_model_as_a_failed_tool_call(self):
        answers = [m for m in self.outcome['state']['messages'] if m.type == 'tool']
        self.assertEqual([m.status for m in answers], ['success', 'error'])
        self.assertTrue(answers[1].content.startswith(REFUSED))


class OpenAIAgents(Example, unittest.TestCase):
    module = openai_agents_example

    def test_the_model_was_handed_the_refusal(self):
        # The last call to the stand-in model holds the answers to both calls, as the model was sent them.
        answers = [i['output'] for i in self.outcome['model'].last_call.input
                   if isinstance(i, dict) and i.get('type') == 'function_call_output']
        self.assertEqual(len(answers), 2)
        self.assertTrue(answers[1].startswith(REFUSED))


class PydanticAI(Example, unittest.TestCase):
    module = pydantic_ai_example

    def test_the_refusal_went_back_to_the_model_as_a_failed_tool_call(self):
        answers = [part for message in self.outcome['result'].all_messages() for part in message.parts
                   if part.part_kind == 'tool-return']
        self.assertEqual([a.outcome for a in answers], ['success', 'failed'])
        self.assertTrue(answers[1].content.startswith(REFUSED))


class NothingIsSent(unittest.TestCase):
    # A documentation address (RFC 5737): each attempt is refused before any packet is sent.
    OUTSIDE = ('192.0.2.1', 443)

    def tearDown(self):
        refused.clear()

    @contextlib.contextmanager
    def refuses(self):
        """The guard itself refused what is inside: the operating system's own
        refusal of a closed port is the same kind of error."""
        before = len(refused)
        with self.assertRaises(ConnectionRefusedError):
            yield
        self.assertGreater(len(refused), before)

    def test_a_look_up_is_refused_while_an_example_runs(self):
        with offline():
            for look_up in (lambda: socket.getaddrinfo('api.example.com', 443), lambda: socket.gethostbyname('api.example.com'),
                            lambda: socket.gethostbyaddr('192.0.2.1'), lambda: socket.getnameinfo(self.OUTSIDE, 0)):
                with self.refuses():
                    look_up()

    def test_a_connection_or_a_message_is_refused(self):
        with offline():
            with self.refuses():
                socket.create_connection(self.OUTSIDE, timeout=1)
            with socket.socket() as s, self.refuses():
                s.connect(self.OUTSIDE)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s, self.refuses():
                s.sendto(b'x', self.OUTSIDE)

    def test_a_connection_through_the_event_loop_is_refused(self):
        # On Windows the event loop's connections raise no audit event, and are checked apart.
        async def connect():
            await asyncio.open_connection(*self.OUTSIDE)

        with offline(), self.refuses():
            asyncio.run(connect())

    def test_a_program_on_this_computer_is_not_reached_but_this_program_is(self):
        with offline():
            # A port on this computer that no socket of this program holds, as a proxy's would be.
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                port = s.getsockname()[1]
            with socket.socket() as s, self.refuses():
                s.connect(('127.0.0.1', port))
            # Python's own event loop on Windows connects one of its sockets to another.
            a, b = socket.socketpair()
            a.close()
            b.close()
            asyncio.run(asyncio.sleep(0))

    def test_starting_another_program_is_refused(self):
        with offline(), self.refuses():
            subprocess.run([sys.executable, '-c', 'pass'])


if __name__ == '__main__':
    unittest.main()
