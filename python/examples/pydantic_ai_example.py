# An agent built with Pydantic AI, whose tools are recorded by Provared.
#
# The model is Pydantic AI's own stand-in, FunctionModel, scripted to ask
# for one order inside the slip, then one over its limit, and then to
# answer. No AI service is called and nothing is sent anywhere: model
# requests to any service are switched off below (ALLOW_MODEL_REQUESTS),
# instrumentation is switched off, Logfire is not installed (the package
# pydantic-ai-slim brings only "logfire-api", which does nothing by
# itself), no API key is set, and the run is made inside _world.offline(),
# which refuses any connection outside this program. Pydantic AI also prints a banner in a
# terminal that invites the reader to set up an observability service; it
# is switched off too (it sends nothing either way).
#
# Run it from this folder: python pydantic_ai_example.py

import pydantic_ai
from pydantic_ai import Agent, ToolFailed
from pydantic_ai import models
from pydantic_ai.capabilities import Hooks
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.tools import Tool

from provared import NotTaken, check_book, record_function

from _world import MESSAGE, ORDER, SUPPLIER, World, offline, order_amount, summary

# No request to any AI service, no instrumentation and no banner, for any agent.
models.ALLOW_MODEL_REQUESTS = False
Agent.instrument_all(False)
pydantic_ai.BANNER_ENABLED = False


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


def record(world, tools):
    """Each tool behind the stub writer. The recorded function keeps the
    tool's name, parameters, type hints and docstring, so Pydantic AI
    describes it to the model exactly as it would the tool itself.
    Pydantic AI runs an ordinary function in a thread of its own, so the
    stub writer's waiting holds up nothing else."""
    return [
        record_function(world.writer, tools['order_supplies'], ORDER, with_=SUPPLIER, amount=order_amount),
        record_function(world.writer, tools['send_message'], MESSAGE),
    ]


def describe(func):
    """How Pydantic AI describes a function to a model: its name, its
    description and the JSON schema of its parameters."""
    d = Tool(func, takes_ctx=False).tool_def
    return {'name': d.name, 'description': d.description, 'parameters': d.parameters_json_schema}


def not_taken(ctx, *, call, tool_def, args, error):
    """A call that the slip does not allow raises NotTaken, and the tool is
    not run. Its message goes back to the model as a failed tool result
    (ToolFailed), which does not ask the model to try the same call again.
    Any other error is passed on, as Pydantic AI does by default."""
    if isinstance(error, NotTaken):
        raise ToolFailed(error.message)
    raise error


def call(name, args, n):
    return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id=f'call-{n}')])


SCRIPT = [
    call('order_supplies', {'item': 'printer paper', 'quantity': 5, 'total_gbp': 30}, 1),
    call('order_supplies', {'item': 'standing desk', 'quantity': 1, 'total_gbp': 250}, 2),
    ModelResponse(parts=[TextPart('I ordered the printer paper. The standing desk was not ordered: it would go over '
                                  'the limit you set. Please order it yourself, or give me a new slip.')]),
]


def main(show=print):
    world = World()
    plain = make_tools(world)
    script = iter(SCRIPT)
    told = {}

    def scripted(messages, info):
        """The stand-in model: it keeps what it was told of the tools, and
        gives the next scripted reply."""
        told.setdefault('tools', info.function_tools)
        return next(script)

    agent = Agent(FunctionModel(scripted), tools=record(world, plain),
                  instructions='You order office supplies within the slip you were given.',
                  capabilities=[Hooks(tool_execute_error=not_taken)])

    with offline():
        result = agent.run_sync('Order paper and a standing desk.')

    described = {d.name: {'name': d.name, 'description': d.description, 'parameters': d.parameters_json_schema}
                 for d in told['tools']}
    show('Pydantic AI agent, with a scripted stand-in model (no AI service is called).')
    show('The tools, as the model was told of them:')
    for d in described.values():
        show(f"  {d['name']}({', '.join(d['parameters']['properties'])}): {d['description']}")
    for message in result.all_messages():
        for part in message.parts:
            if isinstance(part, ToolCallPart):
                show(f'The model asked for {part.tool_name} with {part.args}.')
            elif isinstance(part, ToolReturnPart):
                show(f'  The agent was told: {part.model_response_str()}')
    show(f'The agent answered: {result.output}')
    check = check_book(world.writer.book(), issuer_keys=world.issuer_keys)
    show(summary(check))
    return {'world': world, 'plain': plain, 'described': described, 'result': result, 'check': check}


if __name__ == '__main__':
    main()
