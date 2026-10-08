# A Pydantic AI capability that puts every tool call of an agent behind
# Provared's stub writer.
#
# Each call asks the check before acting first, runs the tool only if the
# person's slip allows the action, and leaves a signed stub that names the
# fingerprint of the call's arguments. A call that the slip does not allow
# is not run, and the model is told why, as a failed tool answer.
#
# It uses only the public interface of the "provared" package (record_tools,
# NotTaken, Refusal) and Pydantic AI's own capability hooks.

import asyncio
import contextvars
from collections.abc import Mapping
from dataclasses import KW_ONLY, dataclass
from typing import Any

from provared import NotTaken, Refusal, record_tools
from pydantic_ai import ToolFailed
from pydantic_ai.capabilities import AbstractCapability

__all__ = ['ProvaredCapability']
__version__ = '0.1.0'

_UNLISTED = ('refuse', 'run')


@dataclass
class ProvaredCapability(AbstractCapability[Any]):
    """Records every tool call of a Pydantic AI agent with Provared.

    writer: the stub writer (provared.open_recorder), for the slip the
    person signed for this agent.
    tools: a dict of the agent's tools by name. For each tool, the action
    name the slip uses for what it does, or a dict as for a tool of
    provared.record_tools, without "run": "action", and where they apply
    "with", "amount", "details", "countersign" and "approve". A function
    among them is handed the arguments after Pydantic AI has checked them
    against the tool's schema, as the tool is handed them.
    unlisted: what to do with a call of a tool that is not in "tools":
    "refuse" (the default: the tool is not run, and the model is told so)
    or "run" (the tool is run, and no stub is written). Pydantic AI's own
    tools for the agent's final output are not tool calls here, and always
    run.
    on_stub: a function of the stub and the tool's name, called after each
    stub is written, for example to keep the book.

    A call that the slip does not allow, or that cannot be recorded, is not
    run: it raises ToolFailed, which Pydantic AI hands to the model as a
    failed tool answer that says why. A tool's own exception, and a call
    that is deferred or sent back to the model to try again, leave no stub.
    Raises provared.Refusal, "bad-field", if a tool is not described as set
    out above."""

    writer: Any
    tools: Mapping[str, Any]
    _: KW_ONLY
    unlisted: str = 'refuse'
    on_stub: Any = None

    def __post_init__(self):
        if not isinstance(self.tools, Mapping):
            raise Refusal('bad-field', 'tools: must be a dict of the tools by name.')
        if self.unlisted not in _UNLISTED:
            raise Refusal('bad-field', 'unlisted: must be "refuse" or "run".')
        # Which tool is being run, for this call: each call sets it in its own context.
        self._handler = contextvars.ContextVar(f'pydantic_ai_provared_{id(self)}')
        described = {}
        for name, spec in self.tools.items():
            if isinstance(spec, str):
                spec = {'action': spec}
            if not isinstance(spec, Mapping):
                raise Refusal('bad-field', f'tools.{name}: must be an action name, or a dict that describes the tool.')
            if 'run' in spec:
                raise Refusal('bad-field', f'tools.{name}.run: is not given here. The capability runs the tool that Pydantic AI calls.')
            described[name] = {**spec, 'run': self._run}
        # Each description is checked, and fixed, here: a mistake shows when the agent is built.
        self._recorded = record_tools(self.writer, described, on_stub=self.on_stub)

    @classmethod
    def get_serialization_name(cls):
        # It holds a stub writer, which cannot be written in an agent's spec.
        return None

    def _run(self, args):
        return self._handler.get()(args)

    async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler):
        name = call.tool_name
        tool = self._recorded.get(name)
        if tool is None:
            if self.unlisted == 'run':
                return await handler(args)
            raise ToolFailed(f'The tool "{name}" was not run. Provared records no tool of that name.')
        loop = asyncio.get_running_loop()

        # The stub writer is an ordinary function, and may wait: it is run in
        # a thread of its own. The tool itself runs on this event loop, in
        # the context of that thread, which carries the writer's mark, so a
        # tool that calls the writer is refused at once.
        def run(copy):
            return asyncio.run_coroutine_threadsafe(handler(copy), loop).result()

        try:
            return await asyncio.to_thread(self._recorded_call, tool, args, run)
        except NotTaken as e:
            raise ToolFailed(e.message) from None
        except Refusal as e:
            raise ToolFailed(f'The tool "{name}" was not run. {e.message}') from None

    def _recorded_call(self, tool, args, run):
        token = self._handler.set(run)
        try:
            return tool(args)
        finally:
            self._handler.reset(token)
