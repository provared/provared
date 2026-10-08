# A connector between an agent's tools and the stub writer.
#
# An agent acts by calling tools: functions that its software offers it.
# record_tools puts each tool behind the stub writer (recorder.py), so that
# every call asks first, is run only if the slip allows it, and leaves a
# stub. The agent's software then calls the tools as before.
#
# By default the stub of a call names one document, "arguments": the
# fingerprint of the call's arguments. So the record fixes exactly what was
# asked for, without holding it: whoever kept the arguments can show them
# later, and anyone can work out the fingerprint again.
#
# It names no agent software and depends on none: a tool is any function.
#
# This is the Python version of the JavaScript library's src/tools.js,
# ported one to one. Every function is an ordinary one: a function handed
# in that gives a coroutine is refused.

import inspect
import math
from collections.abc import Mapping

from . import _js
from . import fields as f
from .encoding import Refusal, _well_formed, fingerprint, utf8
from .recorder import _ABSENT, _clone, _refuse_awaitable


def _clone_any(value):
    """structuredClone, with no limit on depth, as the JavaScript connector copies."""
    return _clone(value, most=None)

_MAX_ARGUMENT_DEPTH = 64
"""How deep the arguments of a call may nest."""


class NotTaken(Exception):
    """A call through a recorded tool that was not run: the check before
    acting did not allow it, or the record so far has a problem. "answer" is
    what the check before acting said (allowed, problems, breaches, needs)."""

    def __init__(self, tool, answer):
        found = [*answer['problems'], *answer['breaches']]
        first = found[0] if found else None
        message = f'The tool "{tool}" was not run. ' + (first['message'] if first else 'The check before acting did not allow it.')
        super().__init__(message)
        self.name = 'NotTaken'
        self.message = message
        self.tool = tool
        self.answer = answer


# The arguments written in one form, as RFC 8785 sets out: members sorted
# by name, no spaces, text and numbers as JSON writes them in JavaScript.
# So the same arguments always give the same fingerprint, whatever order
# their members were written in.
def _one_form(value, depth=0):
    if depth > _MAX_ARGUMENT_DEPTH:
        raise Refusal('bad-field', 'The arguments nest too deeply.')
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, str):
        if not _well_formed(value):
            raise Refusal('bad-field', 'The arguments hold text that is not well-formed Unicode.')
        return _js.string(value)
    if isinstance(value, (int, float)):
        try:
            number = _js.number_value(value)
        except OverflowError:
            number = float('inf')
        if isinstance(number, float) and not math.isfinite(number):
            raise Refusal('bad-field', 'The arguments hold a number that JSON cannot write.')
        return _js.number_string(number)
    if type(value) is list:
        return '[' + ','.join(_one_form(item, depth + 1) for item in value) + ']'
    if type(value) is dict and all(isinstance(name, str) for name in value):
        return '{' + ','.join(_one_form(name, depth + 1) + ':' + _one_form(value[name], depth + 1) for name in _js.sort_strings(value.keys())) + '}'
    raise Refusal('bad-field', 'The arguments must be JSON: objects, lists, text, numbers, true, false and null.')


def arguments_fingerprint(args):
    """The fingerprint of the arguments of a call: SHA-256, in base64url, of
    the arguments written in the one form of RFC 8785. It is what a recorded
    tool puts into its stub, as the document "arguments".

    args: JSON: dicts, lists, text, numbers, True, False and None. A whole
    number is taken as JavaScript holds it: one beyond 2^53 - 1 as the
    nearest float.
    Raises a Refusal, "bad-field", if the arguments are not JSON."""
    return fingerprint(utf8(_one_form(args)))


# A copy that nothing else holds. "No arguments" stays as it is.
def _copied(value, what):
    try:
        return _clone_any(value)
    except Exception:
        raise Refusal('bad-field', f'{what} must be plain data.') from None


# What a tool's own function is handed: a copy of its own, and None where
# the tool was called with no arguments.
def _given(args):
    return None if args is _ABSENT else _clone_any(args)


def _at_once(value, what):
    if inspect.isawaitable(value):
        _refuse_awaitable(value, f'{what}: must be an ordinary function that gives its answer at once. It gave a coroutine, which was not run.')
    return value


# A member of a tool's description that is either a value or a function of
# the arguments. A function is handed a copy of the arguments of its own:
# nothing it does to them changes what is recorded, or what the tool is run
# with. It is called by itself, not as a member of the description: it is
# not handed the description, and cannot change it.
def _from(spec, member, args):
    value = spec[member]
    if not callable(value):
        return value
    given = value(_given(args))
    # A coroutine is not plain data, and is refused as such: it is closed, unrun, first.
    if inspect.isawaitable(given) and callable(getattr(given, 'close', None)):
        given.close()
    return given


# The slip asks for the person's approval, none was handed over, and nothing else stands in the way.
def _needs_only_approval(answer):
    return len(answer['problems']) == 0 and len(answer['breaches']) > 0 and all(b['code'] == 'approval-missing' for b in answer['breaches'])


_MEMBERS = ('action', 'run', 'details', 'countersign', 'approve', 'amount', 'with')


def _read(spec, name):
    """A member of a tool's description: an item of a dict, or an attribute
    of any other object. Nothing (undefined) where there is none."""
    if isinstance(spec, Mapping):
        return spec[name] if name in spec else _ABSENT
    return getattr(spec, name, _ABSENT)


def record_tools(recorder, tools, options=None, on_stub=None):
    """Put an agent's tools behind the stub writer. Each tool is then called
    as before, with one argument (or none); the call asks first, runs the
    tool only if the slip allows the action, and writes the stub.

    recorder: the stub writer (open_recorder).
    tools: a dict of the tools by name. For each tool, a dict (or an object
    with these attributes):
      - "action": the action name the slip uses for what this tool does;
      - "run": the tool itself, a function of the arguments. It must not
        call the stub writer.
      Each function is called by itself, and must give its answer at once:
      a function that gives a coroutine is refused.
      - "with" (optional): the id of the service the tool deals with, as the
        slip names it, or a function of the arguments that gives it;
      - "amount" (optional): {"unit", "value"}, or a function of the
        arguments that gives it;
      - "details" (optional): a function of the arguments that gives the
        documents to name in the stub ({"name", "sha256"} each), or False
        for none. By default: one document, "arguments", the fingerprint of
        the arguments (arguments_fingerprint);
      - "countersign" (optional): asks the other side to countersign the
        stub; a function of the stub and the arguments;
      - "approve" (optional): asks the person for their approval where the
        slip asks for one; a function of the request ({"action", "amount"?,
        "with"?, "details"?}) and the arguments, that gives {"record"} or
        None.
    options: {"onStub": a function of the stub and the tool's name, called
    after each stub is written, for example to keep the book}. It may also
    be given as on_stub.

    Returns a dict of the tools by name. A call gives what the tool gives.
    A call that is not allowed raises NotTaken, and the tool is not run. If
    the tool itself fails, its error is passed on and no stub is written
    (see "act" of the stub writer). If "onStub" fails, its error is passed
    on too: the tool has run by then, and its stub is in the book.
    Raises a Refusal, "bad-field", if a tool is not described as set out
    above."""
    act = getattr(recorder, 'act', None)
    if recorder is None or isinstance(recorder, (str, bytes, int, float, bool)) or not callable(act):
        raise Refusal('bad-field', 'recorder: must be a stub writer.')
    if not isinstance(tools, Mapping):
        raise Refusal('bad-field', 'tools: must be an object that holds the tools by name.')
    if not isinstance(options, Mapping):
        options = {}
    # What the tools are put behind is fixed here too.
    told = on_stub if on_stub is not None else options.get('onStub')
    told = told if callable(told) else None
    recorded = {}
    for name in _js.keys(tools) if all(isinstance(n, str) for n in tools) else list(tools):
        if not isinstance(name, str):
            raise Refusal('bad-field', 'tools: must be an object that holds the tools by name.')
        spec = tools[name]
        if spec is None or isinstance(spec, (str, bytes, int, float, bool)):
            raise f.fail(f'tools.{name}', 'must be an object.')
        # What a tool is, is fixed here, through and through: a later change
        # to the caller's own objects changes nothing. Each member is read
        # once: what is checked is what is fixed.
        fixed = {member: _read(spec, member) for member in _MEMBERS}
        if not callable(fixed['run']):
            raise f.fail(f'tools.{name}.run', 'must be a function.')
        f.action_name(None if fixed['action'] is _ABSENT else fixed['action'], f'tools.{name}.action')
        for member in ('countersign', 'approve'):
            if fixed[member] is not _ABSENT and not callable(fixed[member]):
                raise f.fail(f'tools.{name}.{member}', 'must be a function.')
        if fixed['details'] is not _ABSENT and fixed['details'] is not False and not callable(fixed['details']):
            raise f.fail(f'tools.{name}.details', 'must be a function, or false.')
        for member in ('amount', 'with'):
            if not callable(fixed[member]):
                fixed[member] = _copied(fixed[member], f'tools.{name}.{member}')
        recorded[name] = _tool(act, told, name, fixed)
    return recorded


def _tool(act, on_stub, name, spec):
    def call(args=_ABSENT):
        return _call(act, on_stub, name, spec, args)

    call.__name__ = name if name.isidentifier() else 'tool'
    return call


def _call(act, on_stub, name, spec, args):
    # The arguments are copied when the call is made. The fingerprint is
    # made from that copy, and the tool is run with a copy of it. Each of
    # the tool's other functions is handed a copy of its own.
    given = _copied(args, f'The arguments of the tool "{name}"')
    request = {'action': spec['action']}
    # What the tool's own functions give is copied too: a function that kept
    # what it gave cannot change it afterwards.
    amount = _copied(_from(spec, 'amount', given), f'tools.{name}.amount')
    if amount is not _ABSENT and amount is not None:
        request['amount'] = amount
    with_whom = _copied(_from(spec, 'with', given), f'tools.{name}.with')
    if with_whom is not _ABSENT and with_whom is not None:
        request['with'] = with_whom
    if spec['details'] is False:
        details = []
    elif callable(spec['details']):
        details = _at_once(spec['details'](_given(given)), f'tools.{name}.details')
        if details is None:
            details = []
    else:
        details = [] if given is _ABSENT else [{'name': 'arguments', 'sha256': arguments_fingerprint(given)}]
    if not isinstance(details, list):
        raise f.fail(f'tools.{name}.details', 'must give a list of documents.')
    details = _copied(details, f'tools.{name}.details')
    if len(details) > 0:
        request['details'] = details

    more = {}
    countersign = spec['countersign']
    if callable(countersign):
        more['countersign'] = lambda stub: countersign(stub, _given(given))
    run = spec['run']

    def perform():
        return run(_given(given))

    outcome = act(request, perform, more)
    # Where the slip asks for the person's own approval of this action, and
    # that is the one thing missing, the person is asked, once.
    approve = spec['approve']
    if not outcome['done'] and callable(approve) and _needs_only_approval(outcome['answer']):
        approval = _at_once(approve(_clone_any(request), _given(given)), f'tools.{name}.approve')
        if _js.truthy(approval):
            outcome = act(request, perform, {**more, 'approval': approval})
    if not outcome['done']:
        raise NotTaken(name, outcome['answer'])
    if on_stub:
        _at_once(on_stub(outcome['stub'], name), 'onStub')
    return outcome['result']
