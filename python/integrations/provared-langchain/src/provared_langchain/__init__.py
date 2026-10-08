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
import threading
import warnings
from collections.abc import Mapping

import pydantic
from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from provared import NotTaken, Refusal, record_tools

__all__ = ['ProvaredMiddleware']
__version__ = '0.1.0'

_UNLISTED = ('refuse', 'run')
_MEMBERS = ('action', 'with', 'amount', 'details', 'countersign', 'approve')


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
    "with", "amount", "details", "countersign" and "approve".
    unlisted: what to do with a call of a tool that is not in "tools":
    "refuse" (the default: the tool is not run, the model is told so, and
    a RuntimeWarning is given) or "run" (the tool is run, and no stub is
    written).
    on_stub: a function of the stub and the tool's name, called after each
    stub is written, for example to keep the book.

    It must come last among the middleware that wrap tool calls, so that
    nothing between it and the tool can change the call or answer in the
    tool's place; otherwise the first call raises provared.Refusal.

    A call's arguments are first checked against the tool's schema, as
    LangChain would check them, and written in their JSON form: that form
    is what is fingerprinted, what the functions above are handed, and
    what the tool is run with. A call that does not fit the schema, that
    the slip does not allow, or that cannot be recorded, is not run: the
    model is handed a failed tool answer that says why. A tool that answers
    with an error, or raises, leaves no stub; its exception is passed on.
    Raises provared.Refusal, "bad-field", if a tool is not described as set
    out above."""

    def __init__(self, writer, tools, *, unlisted='refuse', on_stub=None):
        super().__init__()
        self._recorded, self._handler = _described(writer, tools, unlisted, on_stub, 'middleware')
        self._unlisted = unlisted

    def wrap_tool_call(self, request, handler):
        _must_be_last(handler)
        tool = self._recorded.get(request.tool_call['name'])
        if tool is None:
            return handler(request) if self._unlisted == 'run' else _undescribed(request)
        args = _checked(request)
        if isinstance(args, ToolMessage):
            return args
        ran = []

        def run(copy):
            ran.append(True)
            return _answered(handler(_with_args(request, copy)), request.tool_call['id'])

        return self._recorded_call(request, tool, args, run, ran)

    async def awrap_tool_call(self, request, handler):
        _must_be_last(handler)
        tool = self._recorded.get(request.tool_call['name'])
        if tool is None:
            return (await handler(request)) if self._unlisted == 'run' else _undescribed(request)
        args = _checked(request)
        if isinstance(args, ToolMessage):
            return args
        call = _OnTheLoop(asyncio.get_running_loop())

        def run(copy):
            return _answered(call.run_tool(lambda: handler(_with_args(request, copy))), request.tool_call['id'])

        return await call.run_writer(lambda: self._recorded_call(request, tool, args, run, call.ran))

    def _recorded_call(self, request, tool, args, run, ran):
        token = self._handler.set(run)
        try:
            return tool(args)
        except (NotTaken, Refusal) as e:
            # Raised by the tool itself, once it was run: passed on, as any error of the tool.
            if ran:
                raise
            return _not_run(request, e.message) if isinstance(e, Refusal) else _failed(request, e.message)
        except _ToolAnsweredWithError as e:
            return e.answer
        finally:
            self._handler.reset(token)


class _OnTheLoop:
    """One recorded call in an asynchronous agent. The stub writer is an
    ordinary function that may wait, so it is run in a thread of its own,
    not one of the event loop's shared threads, which the tool itself may
    need. The tool is run on the event loop, in the context of that thread,
    which carries the writer's mark, so a tool that calls the writer is
    refused at once. Cancelling the call cancels the tool, as it would
    without the writer: no stub is written, and the writer goes on."""

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


def _must_be_last(handler):
    # When another middleware that wraps tool calls comes after this one,
    # LangChain hands this one a function of its own chain, not the tool.
    if getattr(handler, '__module__', None) == 'langchain.agents.factory' and getattr(handler, '__qualname__', '').endswith('.call_inner'):
        raise Refusal('bad-field', 'middleware: ProvaredMiddleware must come last among the middleware that wrap tool calls, '
                                   'so that nothing between it and the tool can change the call. Move it to the end of the list.')


def _checked(request):
    """The arguments, checked against the tool's schema as LangChain checks
    them, in their JSON form; or the failed answer where they do not fit."""
    args = request.tool_call['args']
    schema = getattr(request.tool, 'tool_call_schema', None) if request.tool is not None else None
    if not (isinstance(schema, type) and issubclass(schema, pydantic.BaseModel)):
        return args
    try:
        return schema.model_validate(args).model_dump(mode='json')
    except pydantic.ValidationError as e:
        found = '; '.join(f"{'.'.join(str(p) for p in error['loc']) or 'the arguments'}: {error['msg']}" for error in e.errors())
        return _not_run(request, f'Its arguments do not fit what the tool takes ({found}).')


def _undescribed(request):
    name = request.tool_call['name']
    warnings.warn(f'ProvaredMiddleware: the agent called the tool "{name}", which is not described to it, so it was not run.',
                  RuntimeWarning, stacklevel=3)
    return _not_run(request, 'Provared records no tool of that name.')


def _with_args(request, args):
    """The request, with the copy of the arguments that was fingerprinted."""
    return request.override(tool_call={**request.tool_call, 'args': args})


def _answered(answer, call_id):
    """The tool's answer; raises where it is an error, given as a message or
    as a Command whose update holds the error message for this call."""
    if isinstance(answer, ToolMessage):
        failed = answer.status == 'error'
    else:
        failed = any(isinstance(m, ToolMessage) and m.status == 'error' and m.tool_call_id == call_id for m in _messages_of(answer))
    if failed:
        raise _ToolAnsweredWithError(answer)
    return answer


def _messages_of(command):
    """The messages that a Command's update holds, in any of the forms LangGraph takes."""
    update = getattr(command, 'update', None)
    if isinstance(update, dict):
        pairs = update.items()
    elif isinstance(update, (list, tuple)):
        pairs = [pair for pair in update if isinstance(pair, tuple) and len(pair) == 2]
    else:
        pairs = [('messages', getattr(update, 'messages', None))]
    found = []
    for key, value in pairs:
        if key == 'messages':
            found.extend(value if isinstance(value, (list, tuple)) else [value])
    return found


def _failed(request, message):
    call = request.tool_call
    return ToolMessage(content=message, name=call['name'], tool_call_id=call['id'], status='error')


def _not_run(request, why):
    return _failed(request, f'The tool "{request.tool_call["name"]}" was not run. {why}')
