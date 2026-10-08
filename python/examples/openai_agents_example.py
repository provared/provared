# An agent built with the OpenAI Agents SDK, whose tools are recorded by
# Provared.
#
# The model is the SDK's own stand-in, ScriptedModel (agents.testing),
# scripted to ask for one order inside the slip, then one over its limit,
# and then to answer. No AI service is called and nothing is sent anywhere:
# the agent is handed the model itself, so the SDK makes no client for a
# service and needs no API key (none is set); tracing is switched off
# below; and the run is made inside _world.offline(), which refuses any
# connection outside this program.
#
# Run it from this folder: python openai_agents_example.py

import asyncio
import os

# Tracing off, before the SDK is imported, and again below in code.
os.environ['OPENAI_AGENTS_DISABLE_TRACING'] = '1'

from agents import Agent, RunConfig, Runner, default_tool_error_function, function_tool, set_tracing_disabled
from agents.items import ToolCallItem, ToolCallOutputItem
from agents.testing import ScriptedModel, assistant_message, function_call

from provared import NotTaken, check_book, record_function

from _world import MESSAGE, ORDER, SUPPLIER, World, offline, order_amount, summary

set_tracing_disabled(True)


def make_tools(world):
    """The agent's tools: ordinary functions, with type hints and docstrings.
    They write into the invented world, so a reader can see what ran."""

    def order_supplies(item: str, quantity: int, total_gbp: int) -> str:
        """Order office supplies from the stationery supplier.

        Args:
            item: What to order, for example "printer paper".
            quantity: How many to order.
            total_gbp: The total price in pounds sterling, a whole number.
        """
        world.orders.append({'item': item, 'quantity': quantity, 'total_gbp': total_gbp})
        return f'Ordered {quantity} x {item} for {total_gbp} GBP.'

    def send_message(to: str, text: str) -> str:
        """Send a short message to a person in the office.

        Args:
            to: The person's name.
            text: The message.
        """
        world.messages.append({'to': to, 'text': text})
        return f'Message sent to {to}.'

    return {'order_supplies': order_supplies, 'send_message': send_message}


def not_taken(context, error):
    """A call that the slip does not allow raises NotTaken, and the tool is
    not run. Its message goes back to the model as the tool's answer. Any
    other error gets the SDK's own answer, which does not show the error."""
    if isinstance(error, NotTaken):
        return error.message
    return default_tool_error_function(context, error)


def record(world, tools):
    """Each tool behind the stub writer, then made a tool of the SDK. The
    recorded function keeps the tool's name, parameters, type hints and
    docstring, so the SDK describes it to the model exactly as it would the
    tool itself.

    The recorded function is an ordinary one, and may wait: the stub writer
    signs each stub, takes one call at a time, and, where the other side is
    asked to countersign, gives it up to 30 seconds. The SDK (version
    0.23.1) runs an ordinary function in a thread of its own
    (asyncio.to_thread), not on its event loop, so that waiting holds up
    nothing else. No wrapper is needed for it."""
    return [
        function_tool(record_function(world.writer, tools['order_supplies'], ORDER, with_=SUPPLIER, amount=order_amount),
                      failure_error_function=not_taken),
        function_tool(record_function(world.writer, tools['send_message'], MESSAGE),
                      failure_error_function=not_taken),
    ]


def describe(func):
    """How the SDK describes a function to a model: its name, its
    description and the JSON schema of its parameters."""
    t = function_tool(func)
    return {'name': t.name, 'description': t.description, 'parameters': t.params_json_schema}


SCRIPT = [
    [function_call('order_supplies', {'item': 'printer paper', 'quantity': 5, 'total_gbp': 30}, call_id='call-1')],
    [function_call('order_supplies', {'item': 'standing desk', 'quantity': 1, 'total_gbp': 250}, call_id='call-2')],
    [assistant_message('I ordered the printer paper. The standing desk was not ordered: it would go over '
                       'the limit you set. Please order it yourself, or give me a new slip.')],
]


def main(show=print):
    world = World()
    plain = make_tools(world)
    model = ScriptedModel(SCRIPT)
    agent = Agent(name='Office supplies agent', instructions='You order office supplies within the slip you were given.',
                  model=model, tools=record(world, plain))

    with offline():
        result = asyncio.run(Runner.run(agent, 'Order paper and a standing desk.',
                                        run_config=RunConfig(tracing_disabled=True)))

    # What the model was told of the tools, as the SDK handed them to it.
    described = {t.name: {'name': t.name, 'description': t.description, 'parameters': t.params_json_schema}
                 for t in model.first_call.tools}
    show('OpenAI Agents SDK agent, with a scripted stand-in model (no AI service is called).')
    show('The tools, as the model was told of them:')
    for d in described.values():
        show(f"  {d['name']}({', '.join(d['parameters']['properties'])}): {d['description']}")
    for item in result.new_items:
        if isinstance(item, ToolCallItem):
            show(f'The model asked for {item.raw_item.name} with {item.raw_item.arguments}.')
        elif isinstance(item, ToolCallOutputItem):
            show(f'  The agent was told: {item.output}')
    show(f'The agent answered: {result.final_output}')
    check = check_book(world.writer.book(), issuer_keys=world.issuer_keys)
    show(summary(check))
    return {'world': world, 'plain': plain, 'described': described, 'model': model, 'result': result, 'check': check}


if __name__ == '__main__':
    main()
