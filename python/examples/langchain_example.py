# An agent built with LangChain (create_agent, with LangGraph underneath),
# whose tools are recorded by Provared.
#
# The model is LangChain's own stand-in, GenericFakeChatModel, scripted to
# ask for one order inside the slip, then one over its limit, and then to
# answer. No AI service is called and nothing is sent anywhere: LangSmith
# tracing is switched off below, no API key is set, and the run is made
# inside _world.offline(), which refuses any connection outside this program.
#
# Run it from this folder: python langchain_example.py

import os

# LangSmith tracing off, before LangChain is imported, and again around the
# run (tracing_context below). No LangSmith key is set.
os.environ['LANGSMITH_TRACING'] = 'false'
os.environ['LANGCHAIN_TRACING_V2'] = 'false'

from langchain.agents import create_agent
from langchain.agents.middleware import ToolErrorMiddleware
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool as langchain_tool
from langchain_core.utils.function_calling import convert_to_openai_tool
from langsmith import tracing_context

from provared import NotTaken, check_book, record_function

from _world import MESSAGE, ORDER, SUPPLIER, World, offline, order_amount, summary


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
    tool's name, parameters, type hints and docstring, so LangChain
    describes it to the model exactly as it would the tool itself."""
    return [
        record_function(world.writer, tools['order_supplies'], ORDER, with_=SUPPLIER, amount=order_amount),
        record_function(world.writer, tools['send_message'], MESSAGE),
    ]


def describe(func):
    """How LangChain describes a function to a model: the agent turns it
    into a tool (with langchain_core.tools.tool), and hands the tool to the
    chat model, which writes it in the form its service reads. Here, the
    OpenAI form, as convert_to_openai_tool writes it."""
    return convert_to_openai_tool(langchain_tool(func))


class ScriptedChatModel(GenericFakeChatModel):
    """LangChain's own stand-in chat model, which gives the replies it is
    handed, one after another. LangChain's agent hands a model its tools
    (bind_tools), which the stand-in does not support by itself (it raises
    NotImplementedError). Here it keeps them, in the OpenAI form, so that
    the example can show what the model was told."""

    described: list = []

    def bind_tools(self, tools, **kwargs):
        self.described = [convert_to_openai_tool(t) for t in tools]
        return self


def not_taken(error, request):
    """A call that the slip does not allow raises NotTaken, and the tool is
    not run. Its message goes back to the model as the tool's answer. Any
    other error is passed on, as LangChain does by default."""
    if isinstance(error, NotTaken):
        return error.message
    return None


def call(name, args, n):
    return AIMessage(content='', tool_calls=[{'name': name, 'args': args, 'id': f'call-{n}', 'type': 'tool_call'}])


SCRIPT = [
    call('order_supplies', {'item': 'printer paper', 'quantity': 5, 'total_gbp': 30}, 1),
    call('order_supplies', {'item': 'standing desk', 'quantity': 1, 'total_gbp': 250}, 2),
    AIMessage(content='I ordered the printer paper. The standing desk was not ordered: it would go over '
                      'the limit you set. Please order it yourself, or give me a new slip.'),
]


def main(show=print):
    world = World()
    plain = make_tools(world)
    model = ScriptedChatModel(messages=iter(SCRIPT))
    agent = create_agent(model, tools=record(world, plain), middleware=[ToolErrorMiddleware(not_taken)],
                         system_prompt='You order office supplies within the slip you were given.')

    with offline(), tracing_context(enabled=False):
        state = agent.invoke({'messages': [{'role': 'user', 'content': 'Order paper and a standing desk.'}]})

    show('LangChain agent, with a scripted stand-in model (no AI service is called).')
    show('The tools, as the model was told of them:')
    for d in model.described:
        f = d['function']
        show(f"  {f['name']}({', '.join(f['parameters']['properties'])}): {f['description'].splitlines()[0]}")
    for message in state['messages']:
        if isinstance(message, AIMessage):
            for c in message.tool_calls:
                show(f"The model asked for {c['name']} with {c['args']}.")
            if message.content:
                show(f'The agent answered: {message.content}')
        elif isinstance(message, ToolMessage):
            show(f'  The agent was told: {message.content}')
    check = check_book(world.writer.book(), issuer_keys=world.issuer_keys)
    show(summary(check))
    return {'world': world, 'plain': plain, 'described': {d['function']['name']: d for d in model.described},
            'state': state, 'check': check}


if __name__ == '__main__':
    main()
