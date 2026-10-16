# A Hermes Agent plugin that puts every tool call of the agent behind
# Provared's stub writer.
#
# Each call is checked against the permission the person signed (the slip)
# before it runs. A call the slip does not allow is not run: Hermes hands the
# model a failed tool answer that says why. A call that runs leaves a signed
# stub that names its action and the SHA-256 fingerprint of the arguments the
# tool received, so the record fixes exactly what was asked for without
# holding it.
#
# It uses Hermes's supported plugin interface (a "tool_execution" middleware,
# and the "post_tool_call" and "transform_tool_result" hooks, which it only
# reads), and the public interface of the "provared" package. Hermes loads it,
# so it opens the stub writer from files: the agent's keys, the slip and the
# book, in one folder (folder.py). It runs only in Hermes's own process.

import contextvars
import json
import logging
import os
import re
import sys
import threading
import warnings
from collections import OrderedDict
from collections.abc import Mapping

from provared import NotTaken, arguments_fingerprint
from provared.encoding import now_ms

from .actions import action_for
from .folder import BookChanged, Folder, FolderError

__all__ = ['HermesRecorder', 'register']
__version__ = '0.1.0'

logger = logging.getLogger(__name__)

# The recorded call that the current code runs inside, if any. Hermes copies
# a thread's context into the threads it starts for a call (the sandbox of
# execute_code, a subagent's workers, its hooks), so a call made from inside
# another one, and a report about the call, are known as such.
_CURRENT = contextvars.ContextVar('provared_hermes_call', default=None)

_PASS = object()
"""A call that is not recorded: a tool that only talks to the person, or
Hermes's second pass over the same call."""

_RECENT = 256
"""How many written stubs are remembered by their call, to compare with what
Hermes reports about the call afterwards."""

# Set by Hermes in its plugin host, the separate process that runs plugins
# under plugins.isolation: host (hermes_cli/plugin_isolation.py).
_HOST_ENV = 'HERMES_PLUGIN_HOST_PROCESS'

# Raised by Hermes's executor for a call it gave up on before dispatching it
# (a batch abandoned, or a call stopped while it was being prepared): the
# tool was not run. Each is Hermes's own class, by the module that holds it
# and its name: a class of the same name that a tool raises is not one.
_NOT_DISPATCHED = (('agent.tool_executor', '_BatchAbandoned'), ('agent.terminal_approval_batch', '_CancelledPreparation'))

# The versions of Hermes this plugin has been tested with: from the first
# (included) to the second (not included). The manifest states neither,
# because Hermes skips a plugin whose requires_hermes rejects the running
# version, and its tools then run unchecked; outside this range the plugin
# loads, and refuses every recorded call unless its setting untested_hermes
# says "run".
_TESTED_HERMES = ((0, 21, 7), (0, 22, 0))

# Hermes's report of a call it gave up waiting for, or stopped, holds the
# arguments as the model gave them, while the tool may still run: such a
# report says nothing about what the tool received.
_REPORT_STATUSES = frozenset({None, '', 'ok', 'error', 'blocked'})


class _Call:
    """One recorded call, from its check to its stub."""

    __slots__ = ('tool', 'call_id', 'action', 'checked', 'thread', 'start', 'opened', 'reported', 'blocked', 'inner_used')

    def __init__(self, tool, call_id, action, checked):
        self.tool = tool
        self.call_id = call_id
        self.action = action
        self.checked = checked
        self.thread = threading.get_ident()
        self.start = None
        self.opened = None
        self.reported = None   # the arguments Hermes reports the tool received, if it does while the call runs
        self.blocked = False   # Hermes's own policy stopped the call after the check
        self.inner_used = False  # Hermes's second pass over this same call has been let through


def _refusal(tool, why):
    """A failed tool answer, in the shape Hermes gives its own: the model is told why."""
    return _answer(f'The tool "{tool}" was not run. {why}')


def _answer(message):
    return json.dumps({'error': message}, ensure_ascii=False)


def _failure(result):
    """Whether a tool's result is Hermes's shape of a failed call (an object
    with an "error" member), and the error."""
    data = result
    if isinstance(result, str):
        try:
            data = json.loads(result)
        except ValueError:
            return False, None
    if isinstance(data, Mapping) and data.get('error'):
        return True, data['error']
    return False, None


def _fingerprint(value):
    try:
        return arguments_fingerprint(value)
    except Exception:
        return None


def _coerced(tool_name, args):
    """The arguments as the tool's handler will receive them: Hermes turns a
    number written as text into a number, and so on, by the tool's schema,
    when it dispatches the call. Done here first, so that what is checked and
    fingerprinted is what the tool receives; done again by Hermes, it changes
    nothing. Where Hermes's helper cannot be loaded, the arguments are taken
    as they are, and Hermes's own report of the call (below) corrects them."""
    try:
        from tools.arg_coercion import coerce_tool_args
    except Exception:
        return dict(args)
    try:
        out = coerce_tool_args(tool_name, dict(args))
    except Exception:
        return dict(args)
    return out if isinstance(out, dict) else dict(args)


def _cell(function, name):
    names = getattr(getattr(function, '__code__', None), 'co_freevars', ())
    for found, cell in zip(names, getattr(function, '__closure__', None) or ()):
        if found == name:
            try:
                return cell.cell_contents
            except ValueError:
                return None
    return None


def _last_in_chain(next_call):
    """Whether this middleware is the last of Hermes's tool_execution
    middleware, the one next to the tool: True, False, or None where the shape
    of Hermes's chain (hermes_cli/middleware.py, _run_execution_chain) is not
    the one known, and this cannot tell."""
    index = _cell(next_call, 'index')
    callbacks = _cell(_cell(next_call, 'call_at'), 'callbacks')
    if not isinstance(index, int) or not isinstance(callbacks, list) or not 0 <= index < len(callbacks):
        return None
    return index == len(callbacks) - 1


def _hermes_class(module, name):
    """One of Hermes's own classes, from the module of Hermes that holds it,
    or None where that module has not been loaded (Hermes has loaded it
    wherever it raises the class). Nothing is imported here."""
    found = getattr(sys.modules.get(module), name, None)
    return found if isinstance(found, type) else None


def _cause(e):
    """The tool's own error: Hermes wraps an error raised below a middleware in
    one of its own, which holds the original."""
    original = getattr(e, 'original', None)
    wrapper = _hermes_class('hermes_cli.middleware', '_DownstreamExecutionError')
    return original if wrapper is not None and type(e) is wrapper and isinstance(original, BaseException) else e


def _not_dispatched(e):
    """Whether the error is Hermes's own report of a call it gave up on before
    dispatching it: the class itself, not one that has the same name."""
    return any(cls is not None and type(e) is cls for cls in (_hermes_class(module, name) for module, name in _NOT_DISPATCHED))


_NOT_LAST = ('Provared must be the last tool_execution middleware, the one next to the tool, and another plugin\'s '
             'comes after it: that one could change the call after the check, or answer in the tool\'s place. '
             'Disable that plugin, or this one.')
_CHAIN_UNKNOWN = ('Provared cannot read Hermes\'s chain of tool_execution middleware, so it cannot tell whether another '
                  'plugin\'s middleware comes after it and could change the call after the check. If you accept that, '
                  'set plugins.entries.provared.settings.unknown_chain to "run".')
_IN_HOST = ('Provared needs Hermes to run its plugins in Hermes\'s own process (plugins.isolation: in_process, the '
            'default): in the plugin host it cannot hand the call on to the tool, so no recorded tool call is run.')


def _period_words(period):
    if period is None:
        return 'in all'
    seconds = period // 1000
    for size, word in ((86400, 'day'), (3600, 'hour'), (60, 'minute')):
        if seconds % size == 0:
            n = seconds // size
            return f'in any {word}' if n == 1 else f'in any {n} {word}s'
    return f'in any {seconds} seconds'


class HermesRecorder:
    """Records every tool call of one Hermes process with Provared.

    folder: where the agent's keys, the permissions and the book are
    (folder.py); Hermes's data folder for the plugin by default.
    actions: the person's own action names for some tools, by tool name,
    which win over the plugin's own (actions.py). They cannot stop a tool
    from being recorded.
    problem: a mistake in the plugin's settings. While there is one, no
    recorded tool call is run, and the model is told why.
    unknown_chain: what to do where Hermes's chain of middleware cannot be
    read: "refuse" (the default) or "run"."""

    def __init__(self, folder=None, actions=None, problem=None, unknown_chain='refuse'):
        self.folder = Folder(folder)
        self.actions = dict(actions or {})
        self.problem = problem
        self.unknown_chain = unknown_chain
        self._lock = threading.Lock()
        self._opened = None
        self._tried = None       # the folder's stamp when a change to it was last refused
        self._waiting = None     # why it was refused
        self._fatal = None       # the book cannot be written: nothing more is recorded or run
        self._closed = False
        self._closing = None     # the writer of an unloaded plugin, kept until the calls running under it end
        self._in_flight = {}
        self._recent = OrderedDict()
        self._said_cannot_tell = False

    # --- the stub writer, opened on the first call, and again when the person changes what it acts under ---

    def _ready(self):
        """The open writer, for the folder as it now stands. Called with the lock held. Raises FolderError."""
        if self._closed:
            raise FolderError('The Provared plugin was unloaded.')
        if self._fatal:
            raise FolderError(self._fatal)
        if self._opened is None:
            try:
                self._opened = self.folder.open()
            except BookChanged as e:
                raise self._book_changed(e) from None
            return self._opened
        stamp = self.folder.stamp()
        if stamp != self._opened.stamp:
            # A change (a new permission, a cancellation, a permission taken
            # away) is taken in between calls, never while one runs: the
            # writer that checked a call writes its stub.
            if self._in_flight:
                raise FolderError('The permission in place has changed, and Provared takes the change in once the calls now '
                                  'running have ended. Make this call again then.')
            if stamp == self._tried:
                raise FolderError(self._waiting)
            try:
                self._opened = self.folder.open(previous=self._opened)
            except BookChanged as e:
                raise self._book_changed(e) from None
            except FolderError as e:
                self._tried, self._waiting = stamp, str(e)
                logger.warning('Provared: %s', e)
                raise
            self._tried = self._waiting = None
        return self._opened

    def _book_changed(self, e):
        """The book file is not what this process wrote: nothing more is recorded or run."""
        self._fatal = f'{e} No recorded tool call is run until Hermes is started again.'
        logger.error('Provared: %s', self._fatal)
        return FolderError(self._fatal)

    def _save(self, opened):
        """Write what the book gained. Called with the lock held. Raises FolderError."""
        try:
            opened.save()
        except BookChanged as e:
            raise self._book_changed(e) from None
        except OSError as e:
            logger.error('Provared: the book file %s could not be written (%s). What it gained is kept, and written with the next stub.',
                         opened.folder.book_file, e)

    def close(self):
        """Hermes unloads the plugin. No new call is checked from now on. The
        book stays locked, and its writer open, until the calls already
        running have ended and their stubs are written: a plugin loaded again
        meanwhile finds the book held, and runs none of its recorded calls until
        then."""
        with self._lock:
            self._closed = True
            opened, self._opened = self._opened, None
            if opened is None:
                return
            if any(c.opened is opened for c in self._in_flight.values()):
                self._closing = opened
            else:
                opened.close()

    def _ended(self, call):
        """A call has ended, with its stub written or not. Called with the lock held."""
        self._in_flight.pop(id(call), None)
        closing = self._closing
        if closing is not None and not any(c.opened is closing for c in self._in_flight.values()):
            self._closing = None
            closing.close()

    # --- the middleware ---

    def on_tool_execution(self, tool_name='', args=None, next_call=None, tool_call_id='', **_):
        """Hermes's "tool_execution" middleware: check, run, receipt.

        Hermes runs the tool anyway when a middleware raises before it calls
        next_call, so nothing here may raise before then: whatever goes wrong
        is a refusal."""
        tool = str(tool_name or '')
        try:
            step = self._before(tool, str(tool_call_id or ''), args, next_call)
        except Exception as e:  # noqa: BLE001 -- refused, never let through
            logger.exception('Provared: the check of a call of "%s" failed', tool)
            return _refusal(tool, f'Provared could not check it ({type(e).__name__}: {e}).')
        if step is _PASS:
            return next_call(args)
        if not isinstance(step, _Call):
            return step
        call = step
        token = _CURRENT.set(call)
        raised = None
        result = None
        try:
            result = next_call(call.checked)
        except BaseException as e:  # noqa: BLE001 -- recorded, then raised again
            raised = e
        finally:
            _CURRENT.reset(token)
        try:
            if call.blocked or (raised is not None and _not_dispatched(_cause(raised))):
                self._finish(call)  # not run: no stub
            else:
                self._receipt(call, result, raised)
        except Exception:  # noqa: BLE001 -- the call has run; its result or error goes back as it is
            logger.exception('Provared: the stub for a call of "%s" was not written. The action was taken and is not in the record.', tool)
            self._finish(call)
        if raised is not None:
            raise raised
        return result

    def _before(self, tool, call_id, args, next_call):
        """Everything before the tool: _PASS (run it, unrecorded), a refusal
        (an answer for the model), or the call, checked and counted as running."""
        given = args if isinstance(args, Mapping) else {}
        outer = _CURRENT.get()
        # Hermes's second pass over the same call (AIAgent._invoke_tool, with its
        # defaults, runs the middleware around a call and again inside it): in
        # the same thread, once, with the same arguments. It is checked and
        # receipted by the outer pass. Anything else is a call of its own.
        if (outer is not None and call_id and outer.call_id == call_id and outer.tool == tool
                and outer.thread == threading.get_ident() and not outer.inner_used and _coerced(tool, given) == outer.checked):
            outer.inner_used = True
            return _PASS
        checked = _coerced(tool, given)
        action = action_for(tool, checked, self.actions)
        if action is None:
            return _PASS
        if os.environ.get(_HOST_ENV) or not callable(next_call):
            return _refusal(tool, _IN_HOST)
        if self.problem is not None:
            return _refusal(tool, self.problem)
        last = _last_in_chain(next_call)
        if last is False:
            warnings.warn(f'Provared: the tool "{tool}" was not run. {_NOT_LAST}', RuntimeWarning, stacklevel=3)
            return _refusal(tool, _NOT_LAST)
        if last is None:
            if self.unknown_chain != 'run':
                return _refusal(tool, _CHAIN_UNKNOWN)
            if not self._said_cannot_tell:
                self._said_cannot_tell = True
                logger.warning('Provared cannot read Hermes\'s chain of tool_execution middleware, and goes on, as its '
                               'setting unknown_chain says.')
        fingerprint = _fingerprint(checked)
        request = {'action': action}
        if fingerprint is not None:
            request['details'] = [{'name': tool[:180], 'sha256': fingerprint}]
        call = _Call(tool, call_id, action, checked)
        with self._lock:
            try:
                opened = self._ready()
            except FolderError as e:
                return _refusal(tool, f'Provared cannot record it: {e}')
            now = now_ms()
            # A limit on how many of this action may be taken holds calls still
            # running as well as stubs written: a call is run only while the
            # stubs in the period, the calls running and this one fit.
            running = sum(1 for c in self._in_flight.values() if c.action == action and c.opened is opened)
            if running:
                for count, period in opened.count_limits(action):
                    if opened.used(action, period, now) + running + 1 > count:
                        return _refusal(tool, f'Calls of this action ({action}) already running would use the rest of what the '
                                              f'permission allows ({count} {_period_words(period)}), so Provared does not run '
                                              'this one now. Make it again once they have ended.')
            answer = opened.writer.before(request, {'when': now})
            try:
                self._save(opened)  # a cancellation the writer held may have gone into the book
            except FolderError as e:
                return _refusal(tool, f'Provared cannot record it: {e}')
            if not answer['allowed']:
                return _answer(NotTaken(tool, answer).message)
            call.start = now
            call.opened = opened
            self._in_flight[id(call)] = call
        return call

    def _finish(self, call):
        with self._lock:
            self._ended(call)

    def _receipt(self, call, result, raised):
        """The stub of a call that reached the tool: for a call that failed, or
        raised, the tool is named as failed, with the fingerprint of the error.
        It is dated when the call started, unless a stub of the chain is dated
        later (a chain does not go back in time)."""
        final = call.reported if isinstance(call.reported, dict) else call.checked
        changed = final != call.checked
        action = action_for(call.tool, final, self.actions) or call.action
        if raised is not None:
            cause = _cause(raised)
            failed, error = True, f'{type(cause).__name__}: {cause}'
        else:
            failed, error = _failure(result)
        fingerprint = _fingerprint(final)
        details = []
        if fingerprint is not None:
            name = call.tool[:180]  # a document's name is at most 200 characters
            details.append({'name': f'{name} (failed)' if failed else name, 'sha256': fingerprint})
        if failed:
            error_fingerprint = _fingerprint(error)
            if error_fingerprint is not None:
                details.append({'name': 'error', 'sha256': error_fingerprint})
        request = {'action': action}
        if details:
            request['details'] = details
        with self._lock:
            try:
                opened = call.opened
                if opened.closed or self._fatal:
                    logger.error('Provared: the stub for this call of "%s" (%s) was not written: the book could not be written '
                                 'while it ran. The action was taken and is not in the record.', call.tool, action)
                    return
                when = max(call.start, opened.last_when)
                try:
                    opened.writer.record(request, {'when': when})
                except Exception as e:  # noqa: BLE001
                    logger.error('Provared: the stub for this call of "%s" (%s) was not written: %s. The action was taken and is '
                                 'not in the record.', call.tool, action, getattr(e, 'message', e))
                    warnings.warn(f'Provared: the stub for this call of "{call.tool}" was not written: {getattr(e, "message", e)}. '
                                  'The action was taken and is not in the record.', RuntimeWarning, stacklevel=3)
                    return
                opened.note_stub(action, when)
                try:
                    self._save(opened)
                except FolderError:
                    pass  # said, and nothing more is run
                if call.call_id:
                    self._recent[(call.call_id, call.tool)] = fingerprint
                    while len(self._recent) > _RECENT:
                        self._recent.popitem(last=False)
            finally:
                self._ended(call)
        if changed:
            logger.warning('Provared: the arguments of this call of "%s" were changed after the check, by Hermes or by another '
                           'plugin\'s pre_tool_call hook. The stub names the arguments the tool received.', call.tool)
            warnings.warn(f'Provared: the arguments of this call of "{call.tool}" were changed after the check. '
                          'The stub names the arguments the tool received.', RuntimeWarning, stacklevel=3)

    # --- the hooks, which only read what Hermes reports ---

    def _reported(self, tool_name, args, tool_call_id, status=None):
        tool = str(tool_name or '')
        call_id = str(tool_call_id or '')
        if not call_id or status not in _REPORT_STATUSES:
            return
        current = _CURRENT.get()
        with self._lock:
            # The call this report is about: the one running in this context.
            # A report with a status (post_tool_call's; "blocked" makes a call
            # leave no stub) is taken only from there. One without (the
            # arguments of transform_tool_result) is also taken for the only
            # call running with that id and tool; where two such calls run at
            # once, it is not used.
            if current is not None and id(current) in self._in_flight and current.call_id == call_id and current.tool == tool:
                matches = [current]
            else:
                matches = [c for c in self._in_flight.values() if c.call_id == call_id and c.tool == tool]
                if status is not None and matches:
                    return
            if len(matches) == 1:
                running = matches[0]
                if status == 'blocked':
                    running.blocked = True
                elif isinstance(args, Mapping):
                    running.reported = dict(args)
                return
            if matches:
                return
            written = self._recent.pop((call_id, tool), None) if status != 'blocked' else None
        # Reported after the stub was written (for some of Hermes's own tools,
        # after the call has returned): what the stub named is compared, once.
        if written is not None and isinstance(args, Mapping):
            if _fingerprint(_coerced(tool, args)) != written:
                logger.warning('Provared: the stub for call %s of "%s" names other arguments than those Hermes reports the tool '
                               'received: they were changed after the check, by Hermes or by another plugin\'s pre_tool_call hook.',
                               call_id, tool)
                warnings.warn(f'Provared: the stub for call {call_id} of "{tool}" names other arguments than those Hermes reports '
                              'the tool received.', RuntimeWarning, stacklevel=2)

    def on_post_tool_call(self, tool_name='', args=None, tool_call_id='', status=None, **_):
        """Hermes's "post_tool_call" hook, read only: a call that Hermes's own
        policy blocked after the check, and the arguments a call ran with."""
        self._reported(tool_name, args, tool_call_id, status)

    def on_transform_tool_result(self, tool_name='', args=None, tool_call_id='', **_):
        """Hermes's "transform_tool_result" hook, read only: the arguments a
        call ran with. It changes no result."""
        self._reported(tool_name, args, tool_call_id)
        return None


def _settings(ctx):
    """The plugin's settings, plugins.entries.provared.settings in Hermes's
    config.yaml: "folder", "actions", "unknown_chain" and "untested_hermes".
    A mistake is not raised, because a plugin that fails to load leaves Hermes
    running without it: it is kept, and every recorded tool call is refused
    until it is put right. Gives back (folder, actions, unknown_chain,
    untested_hermes, problem)."""
    from provared import Refusal
    from provared.fields import action_name

    folder = ctx.get_config('folder')
    actions = ctx.get_config('actions')
    choices = {}
    for name in ('unknown_chain', 'untested_hermes'):
        value = ctx.get_config(name)
        if value in (None, ''):
            value = 'refuse'
        if value not in ('refuse', 'run'):
            return None, None, 'refuse', 'refuse', f'The setting "{name}" of the Provared plugin must be "refuse" or "run".'
        choices[name] = value
    if folder is not None and folder != '' and (not isinstance(folder, str) or not folder.strip()):
        return None, None, 'refuse', 'refuse', 'The setting "folder" of the Provared plugin must be the path of a folder.'
    if actions is None:
        actions = {}
    if not isinstance(actions, Mapping):
        return None, None, 'refuse', 'refuse', 'The setting "actions" of the Provared plugin must map tool names to action names.'
    for tool, name in actions.items():
        try:
            action_name(name, f'actions.{tool}')
        except Refusal as e:
            return None, None, 'refuse', 'refuse', f'The setting "actions" of the Provared plugin has a mistake: {e.message}'
    folder = folder.strip() if isinstance(folder, str) and folder.strip() else None
    return folder, dict(actions), choices['unknown_chain'], choices['untested_hermes'], None


def _version(text):
    """A version as Hermes reads one for requires_hermes: "v1.2.3-rc1" and
    "1.2.3rc1" are (1, 2, 3); None where a part has no leading digits."""
    parts = re.split(r'[-+]', str(text).strip().lstrip('v'), maxsplit=1)[0].split('.')
    parts += ['0'] * (3 - len(parts))
    out = []
    for part in parts[:3]:
        digits = re.match(r'[0-9]+', part.strip())
        if digits is None:
            return None
        out.append(int(digits.group(0)))
    return tuple(out)


def _untested_hermes(choice):
    """Why no recorded call is run, where the Hermes that is running is not
    one this plugin was tested with, or None. With the setting
    untested_hermes "run", it is said in Hermes's log and the plugin goes on."""
    try:
        from hermes_cli.plugins_manifest import running_hermes_version
        running = str(running_hermes_version())
    except Exception:  # noqa: BLE001 -- cannot tell: taken as untested
        running = None
    found = _version(running) if running is not None else None
    low, high = _TESTED_HERMES
    if found is not None and low <= found < high:
        return None
    tested = f'Hermes {".".join(map(str, low))} or a later {low[0]}.{low[1]} version (it was tested with {".".join(map(str, low))})'
    which = f'This is Hermes {running}' if found is not None else 'Provared cannot tell which version of Hermes this is'
    if choice == 'run':
        logger.warning('Provared: %s, and it is made for %s. It goes on, as its setting untested_hermes says.', which, tested)
        return None
    return (f'{which}, and Provared is made for {tested}: another Hermes may hand a tool call on in a way this plugin '
            'does not check, so no recorded tool call is run. If you accept that, set '
            'plugins.entries.provared.settings.untested_hermes to "run".')


def register(ctx):
    """Hermes calls this when it loads the plugin."""
    try:
        folder, actions, unknown_chain, untested, problem = _settings(ctx)
    except Exception as e:  # noqa: BLE001 -- refuse rather than fail to load
        folder, actions, unknown_chain, untested, problem = None, None, 'refuse', 'refuse', f'The settings of the Provared plugin cannot be read: {e}'
    if problem is None:
        problem = _untested_hermes(untested)
    recorder = HermesRecorder(folder, actions, problem, unknown_chain)
    ctx.register_middleware('tool_execution', recorder.on_tool_execution)
    ctx.register_hook('post_tool_call', recorder.on_post_tool_call)
    ctx.register_hook('transform_tool_result', recorder.on_transform_tool_result)
    from . import cli
    ctx.register_cli_command(name='provared', help='Provared: the keys, the permission and the book of this agent',
                             setup_fn=cli.setup, handler_fn=lambda args: cli.run(args, recorder.folder.path),
                             description=cli.DESCRIPTION)
    ctx.on_unload(recorder.close)
    return recorder
