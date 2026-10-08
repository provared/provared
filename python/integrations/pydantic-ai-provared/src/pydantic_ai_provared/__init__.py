# A Pydantic AI capability that puts every tool call of an agent behind
# Provared's stub writer.
#
# Each call asks the check before acting first, runs the tool only if the
# person's slip allows the action, and leaves a signed stub that names the
# fingerprint of the call's arguments. A call that the slip does not allow
# is not run, and the model is told why, as a failed tool answer.
#
# It uses only the public interface of the "provared" package (record_tools,
# NotTaken, Refusal) and Pydantic AI's own capabilities and toolsets.

import asyncio
import contextvars
import threading
import warnings
from collections.abc import Mapping
from dataclasses import KW_ONLY, dataclass
from typing import Any

from provared import NotTaken, Refusal, record_tools
from pydantic_ai import ToolFailed
from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.toolsets import WrapperToolset

__all__ = ['ProvaredCapability']
__version__ = '0.1.0'

_UNLISTED = ('refuse', 'run')
_MEMBERS = ('action', 'with', 'amount', 'details', 'countersign', 'approve')


@dataclass
class ProvaredCapability(AbstractCapability[Any]):
    """Records every tool call of a Pydantic AI agent with Provared.

    writer: the stub writer (provared.open_recorder), for the slip the
    person signed for this agent.
    tools: a dict of the agent's tools by name, as the tools themselves are
    named (before any prefix a toolset adds). For each tool, the action
    name the slip uses for what it does, or a dict as for a tool of
    provared.record_tools, without "run": "action", and where they apply
    "with", "amount", "details", "countersign" and "approve".
    unlisted: what to do with a call of a tool that is not in "tools":
    "refuse" (the default: the tool is not run, the model is told so, and
    a RuntimeWarning is given) or "run" (the tool is run, and no stub is
    written). Pydantic AI's own tools for the agent's final output are not
    tool calls here, and always run.
    on_stub: a function of the stub and the tool's name, called after each
    stub is written, for example to keep the book.

    It wraps each of the agent's own sets of tools, so it checks and
    records each call with the arguments the tool is handed, after every
    other capability's hooks, wherever it stands in the list. The
    arguments must be plain data. A call that the slip does not allow, or
    that cannot be recorded, is not run: it raises ToolFailed, which
    Pydantic AI hands to the model as a failed tool answer that says why.
    A tool that raises, asks the model to try again or reports a failure
    leaves no stub. Raises provared.Refusal, "bad-field", if a tool is not
    described as set out above."""

    writer: Any
    tools: Mapping[str, Any]
    _: KW_ONLY
    unlisted: str = 'refuse'
    on_stub: Any = None

    def __post_init__(self):
        self._recorded, self._handler = _described(self.writer, self.tools, self.unlisted, self.on_stub, 'capability')

    @classmethod
    def get_serialization_name(cls):
        # It holds a stub writer, which cannot be written in an agent's spec.
        return None

    def get_wrapper_toolset(self, toolset):
        # Each set of tools is wrapped where it stands, inside every other wrapper.
        return toolset.visit_and_replace(lambda leaf: _RecordedToolset(leaf, self))


@dataclass
class _RecordedToolset(WrapperToolset[Any]):
    capability: Any = None

    async def call_tool(self, name, tool_args, ctx, tool):
        capability = self.capability
        recorded = capability._recorded.get(name)
        if recorded is None:
            if capability.unlisted == 'run':
                return await self.wrapped.call_tool(name, tool_args, ctx, tool)
            warnings.warn(f'ProvaredCapability: the agent called the tool "{name}", which is not described to it, so it was not run.',
                          RuntimeWarning, stacklevel=2)
            raise ToolFailed(f'The tool "{name}" was not run. Provared records no tool of that name.')
        call = _OnTheLoop(asyncio.get_running_loop())

        def run(copy):
            return call.run_tool(lambda: self.wrapped.call_tool(name, copy, ctx, tool))

        def work():
            token = capability._handler.set(run)
            try:
                return recorded(tool_args)
            finally:
                capability._handler.reset(token)

        try:
            return await call.run_writer(work)
        except (NotTaken, Refusal) as e:
            # Raised by the tool itself, once it was run: passed on, as any error of the tool.
            if call.ran:
                raise
            raise ToolFailed(e.message if isinstance(e, NotTaken) else f'The tool "{name}" was not run. {e.message}') from None


class _OnTheLoop:
    """One recorded call. The stub writer is an ordinary function that may
    wait, so it is run in a thread of its own, not one of the event loop's
    shared threads, which the tool itself may need. The tool is run on the
    event loop, in the context of that thread, which carries the writer's
    mark, so a tool that calls the writer is refused at once. Cancelling
    the call cancels the tool, as it would without the writer: no stub is
    written, and the writer goes on."""

    def __init__(self, loop):
        self._loop = loop
        self._guard = threading.Lock()
        self._tool = None
        self._cancelled = False
        self.ran = []

    def run_tool(self, start):
        with self._guard:
            if self._cancelled:
                raise RuntimeError('The call was cancelled before the tool ran.')
            coroutine = start()
            try:
                self._tool = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
            except BaseException:
                coroutine.close()
                raise
            self.ran.append(True)
        return self._tool.result()

    async def run_writer(self, work):
        future = self._loop.create_future()
        context = contextvars.copy_context()

        def settle(value, error):
            if future.done():
                return
            if error is None:
                future.set_result(value)
            else:
                future.set_exception(error)

        def job():
            value, error = None, None
            try:
                value = context.run(work)
            except Exception as e:
                error = e
            except BaseException as e:  # noqa: BLE001
                error = RuntimeError(f'The stub writer stopped with {type(e).__name__}.')
            try:
                self._loop.call_soon_threadsafe(settle, value, error)
            except RuntimeError:
                pass  # the event loop has closed

        threading.Thread(target=job, daemon=True, name='provared-writer').start()
        try:
            return await future
        except asyncio.CancelledError:
            with self._guard:
                self._cancelled = True
                if self._tool is not None:
                    self._tool.cancel()
            raise


def _described(writer, tools, unlisted, on_stub, what):
    """Each tool's description, checked and fixed: a mistake shows when the agent is built."""
    if not isinstance(tools, Mapping):
        raise Refusal('bad-field', 'tools: must be a dict of the tools by name.')
    if unlisted not in _UNLISTED:
        raise Refusal('bad-field', 'unlisted: must be "refuse" or "run".')
    handler = contextvars.ContextVar(f'provared_{what}_{id(tools)}')
    described = {}
    for name, spec in tools.items():
        if isinstance(spec, str):
            spec = {'action': spec}
        if not isinstance(spec, Mapping):
            raise Refusal('bad-field', f'tools.{name}: must be an action name, or a dict that describes the tool.')
        for member in spec:
            if member == 'run':
                raise Refusal('bad-field', f'tools.{name}.run: is not given here. The {what} runs the tool that the framework calls.')
            if member not in _MEMBERS:
                hint = ' (write "with", not "with_")' if member == 'with_' else ''
                raise Refusal('bad-field', f'tools.{name}.{member}: is not a member of a tool\'s description{hint}. They are: {", ".join(_MEMBERS)}.')
        described[name] = {**spec, 'run': lambda args: handler.get()(args)}
    return record_tools(writer, described, on_stub=on_stub), handler
