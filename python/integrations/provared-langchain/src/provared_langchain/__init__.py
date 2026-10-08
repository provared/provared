# A LangChain middleware that puts every tool call of an agent behind
# Provared's stub writer.
#
# Each call asks the check before acting first, runs the tool only if the
# person's slip allows the action, and leaves a signed stub that names the
# fingerprint of the call's arguments. A call that the slip does not allow
# is not run, and the model is told why, as the tool's answer.
#
# It uses only the public interface of the "provared" package (record_tools,
# NotTaken, Refusal) and LangChain's own middleware hooks.

import asyncio
import contextvars
from collections.abc import Mapping

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from provared import NotTaken, Refusal, record_tools

__all__ = ['ProvaredMiddleware']
__version__ = '0.1.0'

_UNLISTED = ('refuse', 'run')


class _ToolAnsweredWithError(Exception):
    """The tool answered with an error: it did not do what was asked, so its
    stub is not written. The answer is handed back to the model as it is."""

    def __init__(self, answer):
        super().__init__('the tool answered with an error')
        self.answer = answer


class ProvaredMiddleware(AgentMiddleware):
    """Records every tool call of a LangChain agent with Provared.

    writer: the stub writer (provared.open_recorder), for the slip the
    person signed for this agent.
    tools: a dict of the agent's tools by name. For each tool, the action
    name the slip uses for what it does, or a dict as for a tool of
    provared.record_tools, without "run": "action", and where they apply
    "with", "amount", "details", "countersign" and "approve". A function
    among them is handed the arguments as the model gave them, before
    LangChain checks them against the tool's schema.
    unlisted: what to do with a call of a tool that is not in "tools":
    "refuse" (the default: the tool is not run, and the model is told so)
    or "run" (the tool is run, and no stub is written).
    on_stub: a function of the stub and the tool's name, called after each
    stub is written, for example to keep the book.

    A call that the slip does not allow, or that cannot be recorded, is not
    run: the model is handed a failed tool answer that says why. A call
    whose tool answers with an error leaves no stub. A tool's own exception
    is passed on, as LangChain passes it on, and leaves no stub.
    Raises provared.Refusal, "bad-field", if a tool is not described as set
    out above."""

    def __init__(self, writer, tools, *, unlisted='refuse', on_stub=None):
        super().__init__()
        if not isinstance(tools, Mapping):
            raise Refusal('bad-field', 'tools: must be a dict of the tools by name.')
        if unlisted not in _UNLISTED:
            raise Refusal('bad-field', 'unlisted: must be "refuse" or "run".')
        # Which tool is being run, for this call: each call sets it in its own context.
        self._handler = contextvars.ContextVar(f'provared_langchain_{id(self)}')
        described = {}
        for name, spec in tools.items():
            if isinstance(spec, str):
                spec = {'action': spec}
            if not isinstance(spec, Mapping):
                raise Refusal('bad-field', f'tools.{name}: must be an action name, or a dict that describes the tool.')
            if 'run' in spec:
                raise Refusal('bad-field', f'tools.{name}.run: is not given here. The middleware runs the tool that LangChain calls.')
            described[name] = {**spec, 'run': self._run}
        # Each description is checked, and fixed, here: a mistake shows when the agent is built.
        self._recorded = record_tools(writer, described, on_stub=on_stub)
        self._unlisted = unlisted

    def _run(self, args):
        return self._handler.get()(args)

    def wrap_tool_call(self, request, handler):
        def run(args):
            return _answered(handler(_with_args(request, args)))

        return self._call(request, handler, run)

    async def awrap_tool_call(self, request, handler):
        tool = self._recorded.get(request.tool_call['name'])
        if tool is None:
            return await self._unlisted_call(request, handler)
        loop = asyncio.get_running_loop()

        # The stub writer is an ordinary function, and may wait: it is run in
        # a thread of its own. The tool itself runs on this event loop, in
        # the context of that thread, which carries the writer's mark, so a
        # tool that calls the writer is refused at once.
        def run(args):
            return _answered(asyncio.run_coroutine_threadsafe(handler(_with_args(request, args)), loop).result())

        return await asyncio.to_thread(self._recorded_call, request, tool, run)

    def _call(self, request, handler, run):
        tool = self._recorded.get(request.tool_call['name'])
        if tool is None:
            if self._unlisted == 'run':
                return handler(request)
            return _not_run(request, 'Provared records no tool of that name.')
        return self._recorded_call(request, tool, run)

    async def _unlisted_call(self, request, handler):
        if self._unlisted == 'run':
            return await handler(request)
        return _not_run(request, 'Provared records no tool of that name.')

    def _recorded_call(self, request, tool, run):
        token = self._handler.set(run)
        try:
            return tool(request.tool_call['args'])
        except NotTaken as e:
            return _failed(request, e.message)
        except Refusal as e:
            return _not_run(request, e.message)
        except _ToolAnsweredWithError as e:
            return e.answer
        finally:
            self._handler.reset(token)


def _with_args(request, args):
    """The request, with the copy of the arguments that was fingerprinted."""
    return request.override(tool_call={**request.tool_call, 'args': args})


def _answered(answer):
    if isinstance(answer, ToolMessage) and answer.status == 'error':
        raise _ToolAnsweredWithError(answer)
    return answer


def _failed(request, message):
    call = request.tool_call
    return ToolMessage(content=message, name=call['name'], tool_call_id=call['id'], status='error')


def _not_run(request, why):
    return _failed(request, f'The tool "{request.tool_call["name"]}" was not run. {why}')
