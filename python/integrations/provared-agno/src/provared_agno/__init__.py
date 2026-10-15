# An Agno tool hook that puts every tool call of an agent behind Provared's
# stub writer.
#
# Each call asks the check before acting first, runs the tool only if the
# person's slip allows the action, and leaves a signed stub that names the
# fingerprint of the call's arguments. A call that the slip does not allow
# is not run, and the model is told why, as a failed tool answer.
#
# It uses only the public interface of the "provared" package (record_tools,
# NotTaken, Refusal), Agno's own tool hooks, and the call that Agno's chain
# of hooks holds (see _call_of).

import asyncio
import concurrent.futures
import contextvars
import functools
import inspect
import threading
import typing
import warnings
from collections.abc import Mapping

import pydantic
from agno.exceptions import AgentRunException
from agno.tools.function import FunctionCall
from provared import NotTaken, Refusal, record_tools
from pydantic_core import to_jsonable_python

__all__ = ['ProvaredToolHook']
__version__ = '0.1.0'

_UNLISTED = ('refuse', 'run')
_MEMBERS = ('action', 'with', 'amount', 'details', 'countersign', 'approve')

# Agno's own tools that steer the run itself, not the world: a team handing
# work to a member (in a team's ordinary mode, and in its task mode), the
# team's own list of tasks in task mode, and the run's session state. Each
# is known by its name and by the module of Agno's that makes it, so that a
# tool of another origin with the same name is recorded as any other. Where
# the developer describes one, it is recorded under that description. Where
# not, a hand-over passes only to members whose work is recorded (see
# _hand_over_not_recorded), and the others pass unrecorded.
_HAND_OVERS = ('delegate_task_to_member', 'delegate_task_to_members', 'execute_task', 'execute_tasks_parallel')
_TASKS = 'agno.team._task_tools'
_AGNOS_OWN = {
    'delegate_task_to_member': ('agno.team._default_tools',),
    'delegate_task_to_members': ('agno.team._default_tools',),
    'update_session_state': ('agno.team._default_tools', 'agno.agent._default_tools'),
    'execute_task': (_TASKS,),
    'execute_tasks_parallel': (_TASKS,),
    'create_task': (_TASKS,),
    'update_task_status': (_TASKS,),
    'list_tasks': (_TASKS,),
    'add_task_note': (_TASKS,),
    'mark_all_complete': (_TASKS,),
}


class _NotRun(Exception):
    """A call that was not run. Agno hands the message to the model as the
    tool's failed answer."""


class _ToolCancelled(Exception):
    """The tool's own task on the event loop ended cancelled."""


class ProvaredToolHook:
    """Records every tool call of an Agno agent with Provared.

    writer: the stub writer (provared.open_recorder), for the slip the
    person signed for this agent.
    tools: a dict of the agent's tools by name, as the model sees them. For
    each tool, the action name the slip uses for what it does, or a dict as
    for a tool of provared.record_tools, without "run": "action", and where
    they apply "with", "amount", "details", "countersign" and "approve".
    unlisted: what to do with a call of a tool that is not in "tools":
    "refuse" (the default: the tool is not run, the model is told so, and
    a RuntimeWarning is given) or "run" (the tool is run, and no stub is
    written). Agno's own tools that steer the run are not "unlisted": where
    they are not described, the session state and a team's list of tasks
    pass unrecorded, and a team's hand-over of work to a member passes only
    where that member's work is recorded (it carries hooks of the same stub
    writer that record every tool call; a member on another service never
    does); otherwise it is refused. Where described, they are recorded as
    any tool, the step itself, made when Agno starts it.
    on_stub: a function of the stub and the tool's name, called after each
    stub is written, for example to keep the book.

    Give the agent (or the team) its "hooks", and no other tool hook:
    Agent(tool_hooks=hook.hooks). They are this hook, which Agno runs first,
    and a second part, which Agno runs last, next to the tool. In an
    asynchronous run the second part has Agno take every call through its
    asynchronous path, so that no call waits for the stub writer in one of
    the event loop's shared threads, which a tool may need. Given in any
    other way, no tool is run: each call is refused, the model is told why,
    and a RuntimeWarning is given.

    The arguments are read as Agno will hand them to the tool: with the
    defaults of the tool's parameters filled in, and converted by its type
    hints where Agno converts them. Those values are what the tool is
    handed, exactly as without the hook; their JSON form, written
    faithfully (a secret as its value), is what is fingerprinted and what
    the functions above are handed; a parameter left at a default of the
    tool's own with no JSON form is left out of it, and read back takes
    that same default. A call whose arguments do not fit, or
    cannot be written as JSON faithfully, that the slip does not
    allow, or that cannot be recorded, is not run: Agno hands the model a
    failed tool answer that says why. A tool that raises, or that is a
    generator function, leaves no stub; one that raises Agno's
    RetryAgentRun or StopAgentRun leaves one, since it may have acted
    first, and Agno is then handed the exception. Raises
    provared.Refusal, "bad-field", if a tool is not described as set out
    above.

    A copy of the agent (Agent.deep_copy) shares these hooks, and so the one
    stub writer: there is one writer for a book."""

    __name__ = 'provared_tool_hook'

    def __init__(self, writer, tools, *, unlisted='refuse', on_stub=None):
        self._recorded, self._handler = _described(writer, tools, unlisted, on_stub, 'tool hook')
        self._unlisted = unlisted
        self._writer = writer
        self.hooks = (self, _at_the_tool())

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    async def snapshot(self):
        """The stub writer's snapshot() (the book, and the cancellations it
        holds beside it), for asynchronous code. The read waits for a call
        in progress in a thread of its own, not in one of the event loop's
        shared threads, which a tool that holds the writer may need."""
        return await _in_a_thread_of_its_own(self._writer.snapshot)

    # Agno hands a hook only the arguments its parameters name.
    def __call__(self, function_name, function, arguments, agent=None, team=None, run_context=None):
        name = function_name
        call = _call_of(function)
        wrong = _out_of_place(self, function, call, agent, team)
        if wrong is not None:
            warnings.warn(f'ProvaredToolHook: the tool "{name}" was not run. {wrong}', RuntimeWarning, stacklevel=2)
            raise _NotRun(f'The tool "{name}" was not run. {wrong}')
        recorded = self._recorded.get(name)
        steering = _agnos_own(call)
        if steering and recorded is None:
            if name in _HAND_OVERS:
                wrong = _hand_over_not_recorded(self, name, call, arguments, team, run_context)
                if wrong is not None:
                    warnings.warn(f'ProvaredToolHook: the tool "{name}" was not run. {wrong}', RuntimeWarning, stacklevel=2)
                    raise _NotRun(f'The tool "{name}" was not run. {wrong}')
                if name == 'execute_tasks_parallel' and inspect.iscoroutinefunction(function):
                    return _checked_again_as_it_starts(self, name, function(**arguments), call, arguments, team, run_context)
            return function(**arguments)
        if recorded is None:
            if self._unlisted == 'run':
                return function(**arguments)
            warnings.warn(f'ProvaredToolHook: the agent called the tool "{name}", which is not described to it, so it was not run.',
                          RuntimeWarning, stacklevel=2)
            raise _NotRun(f'The tool "{name}" was not run. Provared records no tool of that name.')
        try:
            form, values = _as_agno_hands_them(call)
        except _Unfit as e:
            raise _NotRun(f'The tool "{name}" was not run. {e}') from None
        # A described steering tool of Agno's gives its steps as they come
        # (a hand-over, the member's work): its stub records the step itself.
        handing_over = steering
        # In Agno's asynchronous path the function a hook calls to go on
        # gives a coroutine. The hook then gives a coroutine too, which Agno
        # waits for.
        if inspect.iscoroutinefunction(function):
            return self._on_the_loop(name, recorded, function, call, form, values, handing_over)
        return self._at_once(name, recorded, function, call, form, values, handing_over)

    def _at_once(self, name, recorded, function, call, form, values, handing_over):
        ran, stopped = [], []

        def run(copy):
            ran.append(True)
            # The tool is handed the values that were read and fingerprinted:
            # Agno hands it the call's own arguments.
            call.arguments = dict(values)
            try:
                result = function(**values)
            except AgentRunException as e:
                stopped.append(e)
                return None
            return _not_a_generator(name, result, handing_over)

        token = self._handler.set(run)
        try:
            result = recorded(form)
        except (NotTaken, Refusal) as e:
            # Raised by the tool itself, once it was run: passed on, as any error of the tool.
            if ran:
                raise
            raise _refused(name, e) from None
        finally:
            self._handler.reset(token)
        if stopped:
            raise stopped[0]
        return result

    async def _on_the_loop(self, name, recorded, function, call, form, values, handing_over):
        on_loop = _OnTheLoop(asyncio.get_running_loop(), call)
        stopped = []

        def run(copy):
            # The tool is handed the values that were read and fingerprinted:
            # Agno hands it the call's own arguments.
            call.arguments = dict(values)
            try:
                result = on_loop.run_tool(lambda: function(**values))
            except AgentRunException as e:
                stopped.append(e)
                return None
            return _not_a_generator(name, result, handing_over)

        def work():
            token = self._handler.set(run)
            try:
                return recorded(form)
            finally:
                self._handler.reset(token)

        try:
            result = await on_loop.run_writer(work)
        except (NotTaken, Refusal) as e:
            # Raised by the tool itself, once it was run: passed on, as any error of the tool.
            if on_loop.ran:
                raise
            raise _refused(name, e) from None
        except _ToolCancelled:
            # The tool cancelled itself: the run is cancelled, as it would be without the hook.
            raise asyncio.CancelledError() from None
        if stopped:
            raise stopped[0]
        return result


# --- the second part, next to the tool ---

def _check_last(name, function):
    """What follows: nothing but the tool may."""
    kind = _next_step(function)[0]
    if kind == 'hook':
        warnings.warn(f'ProvaredToolHook: the tool "{name}" was not run. {_OUT_OF_PLACE}', RuntimeWarning, stacklevel=3)
        raise _NotRun(f'The tool "{name}" was not run. {_OUT_OF_PLACE}')
    return kind


async def _go_on(name, function, arguments):
    if _check_last(name, function) != 'ordinary tool':
        return await function(**arguments)
    # An ordinary tool runs in a thread of its own, as Agno runs one in an
    # asynchronous run where no hook is asynchronous. The step that calls it
    # never waits. Once it runs it cannot be stopped: a cancelled call ends
    # only when it does, however often it is cancelled (as where asyncio.run
    # ends and cancels every task left), so that the stub writer is not
    # freed while the tool still acts, and its stub is written if it
    # completes.
    ended = concurrent.futures.Future()
    on_loop = _CALL.get(None)
    if on_loop is not None and on_loop.call is _call_of(function):
        # So that the writer learns how the tool ended where the event loop
        # stops, or closes, before this step can tell it. Only for the call
        # the writer waits for: a call made from inside its tool (by a
        # helper agent, say) carries the same mark, and its thread is not
        # this tool's.
        on_loop.tool_thread = ended
    running = _in_a_thread_of_its_own(_to_its_end, function(**arguments), ended=ended)
    while True:
        try:
            return await asyncio.shield(running)
        except asyncio.CancelledError:
            if running.done():
                return running.result()


def _on_an_event_loop():
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def _coroutine_mark():
    """The attribute and the value with which Python (3.12 and later) marks
    a function as asynchronous (inspect.markcoroutinefunction), read from a
    function it marks; or None."""
    mark = getattr(inspect, 'markcoroutinefunction', None)
    if mark is None:
        return None

    def probe():
        pass

    before = set(vars(probe))
    mark(probe)
    added = [(k, v) for k, v in vars(probe).items() if k not in before]
    return added[0] if len(added) == 1 and inspect.iscoroutinefunction(probe) else None


_MARK = _coroutine_mark()


class _AtTheTool:
    """The second part. Agno takes a tool call through its asynchronous path
    only where a tool hook is asynchronous, and in an ordinary run it skips
    an asynchronous hook. So this part is marked as asynchronous only where
    an event loop runs: in an asynchronous run. In an ordinary run it is an
    ordinary hook, which checks that nothing follows it and goes on."""

    __name__ = 'provared_tool_hook_last_part'

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def __call__(self, function_name, function, arguments):
        if inspect.iscoroutinefunction(function):
            return _go_on(function_name, function, arguments)
        _check_last(function_name, function)
        return function(**arguments)


if _MARK is not None:
    setattr(_AtTheTool, _MARK[0], property(lambda self: _MARK[1] if _on_an_event_loop() else None))


def _at_the_tool():
    if _MARK is not None:
        return _AtTheTool()

    # Where Python cannot mark an object as asynchronous (3.11), the second
    # part is an asynchronous function. Agno then skips it in an ordinary
    # run, and says so.
    async def provared_tool_hook_last_part(function_name, function, arguments):
        return await _go_on(function_name, function, arguments)

    return provared_tool_hook_last_part


# --- threads ---

def _in_a_thread_of_its_own(work, *args, ended=None):
    """Runs work in a thread of its own, in the present context, and gives a
    future of the event loop that holds its result. Not one of the event
    loop's shared threads: those may all be taken by calls that wait for
    the stub writer. "ended", a future of any thread, takes the result too,
    whether or not the event loop still runs."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()
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
            value = context.run(work, *args)
        except Exception as e:
            error = e
        except BaseException as e:  # noqa: BLE001
            error = RuntimeError(f'The work stopped with {type(e).__name__}.')
        if ended is not None:
            if error is None:
                ended.set_result(value)
            else:
                ended.set_exception(error)
        try:
            loop.call_soon_threadsafe(settle, value, error)
        except RuntimeError:
            pass  # the event loop has closed

    threading.Thread(target=job, daemon=True, name='provared').start()
    return future


# The recorded call whose tool the event loop is running: set in the
# writer's thread, and so seen by the tool's task and the second part, and
# by every call made from inside the tool.
_CALL = contextvars.ContextVar('provared_agno_call')


class _OnTheLoop:
    """One recorded call in an asynchronous run. The stub writer is an
    ordinary function that may wait, so it is run in a thread of its own,
    not one of the event loop's shared threads, which the tool itself may
    need. The tool is run as a task of the event loop, in the context of
    that thread, which carries the writer's mark, so a tool that calls the
    writer is refused at once. The writer waits until that task has ended.
    Cancelling the call cancels the task, as it would without the writer:
    no stub is written for a tool that did not complete."""

    def __init__(self, loop, call):
        self._loop = loop
        # Agno's FunctionCall that this is for.
        self.call = call
        self._guard = threading.Lock()
        self._task = None
        self._cancelled = False
        self.ran = []
        # Where the tool is an ordinary one, the future its own thread sets.
        self.tool_thread = None

    def run_tool(self, start):
        """In the writer's thread: starts the tool as a task of the event
        loop, and waits until that task has ended."""
        ended = concurrent.futures.Future()

        # On the event loop, where the call is also cancelled, so that the
        # two cannot cross: a call cancelled before this runs never starts
        # its tool. (Where the event loop has closed, nothing is started.)
        def begin():
            with self._guard:
                if self._cancelled:
                    ended.set_exception(RuntimeError('The call was cancelled before the tool ran.'))
                    return
                self._task = asyncio.ensure_future(start())
                self.ran.append(True)
            self._task.add_done_callback(lambda task: _settle_from(ended, task))

        # The callback runs in a copy of this thread's context, and the task in a copy of that.
        _CALL.set(self)
        self._loop.call_soon_threadsafe(begin)
        while True:
            try:
                return ended.result(timeout=0.2)
            except concurrent.futures.TimeoutError:
                pass
            # Where the event loop no longer runs (stopped, or closed), the
            # task cannot tell how the tool ended. An ordinary tool's own
            # thread can, once it has ended: its stub is then written, and
            # the writer is freed. A tool on a closed event loop never ends.
            thread = self.tool_thread
            running = self._loop.is_running()
            if not running and thread is not None and thread.done():
                return thread.result()
            task = self._task
            if not running and task is not None and task.done():
                # It ended, and the event loop stopped before it could say so.
                if task.cancelled():
                    raise _ToolCancelled()
                if task.exception() is not None:
                    raise task.exception()
                return task.result()
            if thread is None and (self._loop.is_closed() or (not running and self._cancelled)):
                # An asynchronous tool, cancelled or on a closed event loop: it cannot complete.
                raise RuntimeError('The event loop stopped before the cancelled tool had ended, so it did not complete.')

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
                task = self._task
            if task is not None:
                task.cancel()
            raise


def _settle_from(ended, task):
    if task.cancelled():
        ended.set_exception(_ToolCancelled())
    elif task.exception() is not None:
        ended.set_exception(task.exception())
    else:
        ended.set_result(task.result())


def _to_its_end(coroutine):
    """Runs a coroutine that never waits: Agno's step that calls an ordinary tool."""
    try:
        coroutine.send(None)
    except StopIteration as e:
        return e.value
    coroutine.close()
    raise RuntimeError('Agno\'s step that calls an ordinary tool waited, which it does not do.')


# --- describing the tools ---

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


# --- the call, as Agno's chain of hooks holds it ---

_OUT_OF_PLACE = ('ProvaredToolHook must be given as the only tool hooks of the agent, or of the team, whose tools it records: '
                 'Agent(tool_hooks=hook.hooks). Another hook could change the call after the check, or answer in the tool\'s place.')

_UNREADABLE = ('This version of Agno hands the hook a call that it cannot read, so it cannot know what the tool would be handed. '
               'ProvaredToolHook was made for Agno 3.1.')


def _cell(function, name):
    names = getattr(getattr(function, '__code__', None), 'co_freevars', ())
    for found, cell in zip(names, getattr(function, '__closure__', None) or ()):
        if found == name:
            try:
                return cell.cell_contents
            except ValueError:
                return None
    return None


def _call_of(function):
    """The call (Agno's FunctionCall) that the chain of hooks runs: the
    function a hook is handed to go on holds the next step, which holds the
    call. None where the chain is not of the shape that Agno 3.1 builds."""
    call = _cell(_cell(function, 'inner_func'), 'self')
    return call if isinstance(call, FunctionCall) else None


def _next_step(function):
    """What Agno's chain does when a hook calls the function it is handed to
    go on: ("hook", that hook), ("ordinary tool", None) or ("asynchronous
    tool", None); or (None, None) where the chain is not of the shape known."""
    inner = _cell(function, 'inner_func')
    name = getattr(inner, '__name__', None)
    if name == 'wrapper':
        return 'hook', _cell(inner, 'hook')
    if name == 'execute_entrypoint':
        return 'ordinary tool', None
    if name == 'execute_entrypoint_async':
        return 'asynchronous tool', None
    return None, None


def _ours(hook, hooks):
    return isinstance(hooks, (list, tuple)) and len(hooks) == 2 and hooks[0] is hook and hooks[1] is hook.hooks[1]


def _out_of_place(hook, function, call, agent, team):
    """Why the hook may not record this call, or None. The hooks in force
    are those of the agent whose tool is called, or of the team where the
    tool is the team's own; they, and the hooks of the call itself, must be
    the hook's own two parts, and the next step must be its second part;
    or the tool itself, where Agno skips the second part, as it skips a hook
    it takes to be asynchronous in an ordinary run."""
    if call is None:
        return _UNREADABLE
    holder = agent if agent is not None else team
    if not (_ours(hook, getattr(holder, 'tool_hooks', None)) and _ours(hook, call.function.tool_hooks)):
        return _OUT_OF_PLACE
    kind, following = _next_step(function)
    skipped = kind == 'ordinary tool' and not inspect.iscoroutinefunction(function) and inspect.iscoroutinefunction(hook.hooks[1])
    if not (kind == 'hook' and following is hook.hooks[1]) and not skipped:
        return _OUT_OF_PLACE
    return None


def _origin(entrypoint):
    """The function itself behind Agno's wrappers and a functools.partial."""
    found = inspect.unwrap(entrypoint)
    while isinstance(found, functools.partial):
        found = inspect.unwrap(found.func)
    return found


def _hand_over_not_recorded(hook, name, call, arguments, team, run_context):
    """Why a team's hand-over may not pass unrecorded, or None. It passes
    only where every member it reaches carries hooks of this same stub
    writer that record each of its tool calls (see _carries)."""
    if team is None:
        return 'It hands a task over, and no team was given with the call.'
    try:
        if name in ('delegate_task_to_member', 'execute_task'):
            # Agno's own way of finding the member a hand-over names.
            found = team._find_member_by_id(arguments.get('member_id'), run_context=run_context)
            if found is None:
                return None  # No member of that name: Agno answers so, and nothing is handed over.
            members = [found[1]]
        elif name == 'execute_tasks_parallel':
            # Each task goes to the member it is assigned to, in the list of
            # tasks that Agno's own tool holds and goes by: not the copy of it
            # in the session state, which the model may be able to change.
            # The member is found as that tool finds it.
            tasks = _cell(_origin(call.function.entrypoint), 'task_list')
            if tasks is None:
                return 'It hands tasks over, and the list of tasks it goes by cannot be read.'
            members = []
            for task_id in arguments.get('task_ids') or []:
                task = tasks.get_task(task_id)
                found = team._find_member_by_id(task.assignee) if task is not None and task.assignee else None
                if found is None:
                    return f'It names the task "{task_id}", whose member cannot be found, so which member it reaches cannot be told.'
                members.append(found[1])
        else:
            from agno.utils.callables import get_resolved_members
            members = list(get_resolved_members(team, run_context) or [])
    except Exception:
        return 'It hands a task over, and which member it reaches cannot be told.'
    away = [m for m in members if _far(m)]
    loose = [m for m in members if not _far(m) and not _carries(hook, m)]
    if not (away or loose):
        return None
    why = []
    if away:
        why.append(f'{_who(away)} runs on another service, where these hooks cannot record what it does')
    if loose:
        why.append(f'{_who(loose)} carries no tool hooks of this stub writer that record each of its tool calls, '
                   'so what it does would not be recorded')
    found = '; '.join(why)
    return (found[0].upper() + found[1:] + '. Give each member that may act tool_hooks=ProvaredToolHook(writer, ...).hooks with the same '
            f'writer, or describe "{name}" to the hook, to record the hand-over itself.')


async def _checked_again_as_it_starts(hook, name, pending, call, arguments, team, run_context):
    """In an asynchronous run Agno starts a hand-over (an asynchronous
    generator) only once every call of the model's reply has been through
    the hooks, and another call of that reply may give a task to another
    member meanwhile (execute_task, where it is described). So
    execute_tasks_parallel, which hands each task to the member that Agno's
    list of tasks names when it starts, is checked again then. Its first
    step reads those members, and runs straight after this check, with
    nothing between them. (In an ordinary run Agno starts each hand-over
    straight after its hooks.)"""
    handed_over = await pending
    if not inspect.isasyncgen(handed_over):
        return handed_over

    async def as_it_starts():
        try:
            wrong = _hand_over_not_recorded(hook, name, call, arguments, team, run_context)
            if wrong is not None:
                warnings.warn(f'ProvaredToolHook: the tool "{name}" was not run. {wrong}', RuntimeWarning, stacklevel=2)
                raise _NotRun(f'The tool "{name}" was not run. {wrong}')
            async for item in handed_over:
                yield item
        finally:
            await handed_over.aclose()

    return as_it_starts()


def _far(member):
    try:
        from agno.remote.base import BaseRemote
    except ImportError:
        return False  # Then no remote agent or team can have been made.
    return isinstance(member, BaseRemote)


def _carries(hook, member):
    """Whether a member's own tool calls go into this writer's book: it
    carries hooks of the same writer, which refuse a tool they do not
    describe (unlisted="refuse"), unless the team's own hook lets such tools
    run unrecorded too (unlisted="run")."""
    hooks = getattr(member, 'tool_hooks', None)
    first = hooks[0] if isinstance(hooks, (list, tuple)) and len(hooks) == 2 else None
    return (isinstance(first, ProvaredToolHook) and first._writer is hook._writer and hooks[1] is first.hooks[1]
            and (first._unlisted == 'refuse' or hook._unlisted == 'run'))


def _who(members):
    from agno.utils.team import get_member_id

    def label(member):
        # A member on another service is named by its id alone: its other names come from that service.
        found = getattr(member, 'id', None)
        if not found and not _far(member):
            found = get_member_id(member)
        return f'"{found}"' if found else 'one'

    names = [label(m) for m in members]
    return ('the member ' if len(names) == 1 else 'the members ') + ', '.join(names)


def _agnos_own(call):
    modules = _AGNOS_OWN.get(call.function.name)
    return modules is not None and getattr(_origin(call.function.entrypoint), '__module__', None) in modules


# --- the arguments, as Agno will hand them to the tool ---

class _Unfit(Exception):
    """Arguments that cannot be read as Agno would hand them to the tool."""


def _as_agno_hands_them(call):
    """(form, values): the values Agno will hand the tool for this call, and
    their JSON form, written faithfully.

    The values: each parameter the model may give, or the person (a field
    Agno asks the person to fill in), with its default filled in where it
    was not given, and each argument given; converted by its parameter's
    type hint where Agno converts the tool's arguments (pydantic's
    validate_call), and as given where it does not. The parameters Agno
    fills in itself (the agent, the run's context) are never among them:
    Agno takes such a name out of the call's arguments before the hooks.

    The form must read back as the same values, and the values handed over
    must read as themselves, as Agno will read them again; otherwise the
    call cannot be recorded faithfully, and is refused."""
    entrypoint = call.function.entrypoint
    given = dict(call.arguments or {})
    properties = (call.function.parameters or {}).get('properties') or {}
    filled_in = getattr(call.function, 'user_input_fields', None) or []
    names = tuple(dict.fromkeys([*properties, *filled_in, *given]))
    converts = bool(getattr(entrypoint, '_wrapped_for_validation', False))
    try:
        read = _reader(_origin(entrypoint), names, converts)
    except Exception:
        raise _Unfit('Its parameters, or their types, cannot be read.') from None
    try:
        values = read(given)
    except (pydantic.ValidationError, _Unfit) as e:
        raise _Unfit(f'Its arguments do not fit what the tool takes ({_problems(e)}).') from None
    except Exception:
        raise _Unfit('Its arguments do not fit what the tool takes.') from None
    form = _form(values, read.defaults)
    try:
        again, from_form = read(values), read(form)
    except Exception:
        again = from_form = None
    if again != values or from_form != values:
        raise _Unfit('Its arguments do not read back as the values the tool would be handed: they read differently each time, '
                     'or cannot be written as JSON faithfully. So what the tool would be handed cannot be fixed in the record.')
    return form, values


def _form(values, defaults):
    """The JSON form of the values. A parameter left at a default of the
    tool's own that has no JSON form (an object of the program's) is left
    out: read back, it takes that same default again."""
    form = {}
    for name, value in values.items():
        try:
            form[name] = _faithful(value)
        except _Unfit:
            if name in defaults and value is defaults[name]:
                continue
            raise
    return form


def _problems(e):
    if isinstance(e, pydantic.ValidationError):
        return '; '.join(f"{'.'.join(str(p) for p in error['loc']) or 'the arguments'}: {error['msg']}" for error in e.errors())
    return str(e)


def _faithful(value, depth=0):
    """The JSON form of a value, written so that it reads back as the value:
    a secret as its value, a model by the names it is read by. Raises _Unfit
    where there is none."""
    if depth > 64:
        raise _Unfit('Its arguments nest too deeply to be recorded.')
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if value != value or value in (float('inf'), float('-inf')):
            raise _Unfit('Its arguments hold a number that JSON cannot write.')
        return float(value)
    if isinstance(value, (list, tuple)):
        return [_faithful(v, depth + 1) for v in value]
    if isinstance(value, dict):
        # A name that is not text (a number, say) is written as JSON writes it: as text.
        written = {_name(k): _faithful(v, depth + 1) for k, v in value.items()}
        if len(written) != len(value):
            raise _Unfit('Its arguments hold a dict two of whose names are written the same way in JSON.')
        return written
    if isinstance(value, pydantic.SecretStr):
        return value.get_secret_value()
    if isinstance(value, pydantic.SecretBytes):
        try:
            return value.get_secret_value().decode('utf-8')
        except UnicodeDecodeError:
            raise _Unfit('Its arguments hold a secret that is not text.') from None
    if isinstance(value, pydantic.BaseModel):
        # Every field, by the name it is read by, also one pydantic leaves
        # out when it writes JSON (exclude=True), and any extra field.
        written = {}
        for field_name, info in type(value).model_fields.items():
            alias = info.validation_alias if isinstance(info.validation_alias, str) else info.alias
            written[alias or field_name] = getattr(value, field_name)
        written.update(value.model_extra or {})
        return _faithful(written, depth + 1)
    try:
        written = to_jsonable_python(value)
    except Exception:
        raise _Unfit(f'Its arguments hold a value of the type {type(value).__qualname__}, which has no JSON form.') from None
    if written is value:
        raise _Unfit(f'Its arguments hold a value of the type {type(value).__qualname__}, which has no JSON form.')
    return _faithful(written, depth + 1)


def _name(key):
    if isinstance(key, str):
        return key
    written = _faithful(key)
    if isinstance(written, bool) or not isinstance(written, (str, int, float)):
        raise _Unfit('Its arguments hold a dict with a name that JSON cannot write.')
    return written if isinstance(written, str) else str(written)


def _reader(entrypoint, names, converts):
    try:
        return _cached_reader(entrypoint, names, converts)
    except TypeError:  # an entrypoint that cannot be a key
        return _make_reader(entrypoint, names, converts)


@functools.lru_cache(maxsize=256)
def _cached_reader(entrypoint, names, converts):
    return _make_reader(entrypoint, names, converts)


def _make_reader(entrypoint, names, converts):
    """A function of the arguments given that gives the values the tool's
    parameters would be handed: built with pydantic's validate_call as Agno
    builds its own, from the tool's own signature, where Agno converts; and
    taken as they are, with the defaults filled in, where it does not."""
    signature = inspect.signature(entrypoint, eval_str=converts)
    params = []
    for name in names:
        p = signature.parameters.get(name)
        if p is None or p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        annotation = typing.Any if p.annotation is inspect.Parameter.empty else p.annotation
        params.append(inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, default=p.default, annotation=annotation))
    # A tool that takes any named argument (as one from an MCP server does) is handed the others as they were given.
    others = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values())
    if others:
        params.append(inspect.Parameter('provared_others', inspect.Parameter.VAR_KEYWORD, annotation=typing.Any))

    defaults = {p.name: p.default for p in params if p.default is not inspect.Parameter.empty}

    if not converts:
        def as_given(given):
            values = {}
            for p in params:
                if p.kind is inspect.Parameter.VAR_KEYWORD:
                    continue
                if p.name in given:
                    values[p.name] = given[p.name]
                elif p.default is not inspect.Parameter.empty:
                    values[p.name] = p.default
                else:
                    raise _Unfit(f'{p.name}: missing')
            for name, value in given.items():
                if name not in values:
                    if not others:
                        raise _Unfit(f'{name}: not an argument the tool takes')
                    values[name] = value
            return values

        as_given.defaults = defaults
        return as_given

    def arguments(**given):
        return given

    arguments.__signature__ = inspect.Signature(params)
    arguments.__annotations__ = {p.name: p.annotation for p in params}
    validated = pydantic.validate_call(arguments, config=dict(arbitrary_types_allowed=True))

    def converted(given):
        return validated(**given)

    converted.defaults = defaults
    return converted


# --- the tool's answer ---

def _not_a_generator(name, result, handing_over=False):
    # Calling a generator function does not run its body, so its stub would
    # be written for an action not yet taken. It is closed unrun. Agno's own
    # steering tools, where described, are the one exception: their stub
    # records the step itself (a hand-over, a task made), when Agno starts it.
    if handing_over:
        return result
    if inspect.isgenerator(result) or inspect.isasyncgen(result):
        if inspect.isgenerator(result):
            result.close()
        raise _NotRun(f'The tool "{name}" was not run. It is a generator function, whose body runs only as its results are read, '
                      'so its stub would be written for an action not yet taken.')
    return result


def _refused(name, e):
    return e if isinstance(e, NotTaken) else _NotRun(f'The tool "{name}" was not run. {e.message}')
