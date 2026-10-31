# The Provared plugin in a real Hermes agent. The agent runs with Hermes's
# own stand-in model (tests/fakes/fake_llm_provider.py in Hermes's source: a
# server inside this program that answers with replies scripted in advance),
# so no AI service is called. It runs inside the examples' guard, which
# refuses any connection outside this program and the start of any other
# program, with Hermes's telemetry and update checks switched off. The plugin
# is installed as a folder in the Hermes home, as "hermes plugins install"
# installs it, beside a small plugin of invented office tools
# (office_plugin.py) that run inside this program.
#
# Run from this package's folder, with an environment that holds Hermes (an
# editable install of its source at v0.21.7) and Provared:
#   .venv/Scripts/python -m unittest discover -s tests

import contextlib
import importlib.util
import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import unittest
from collections.abc import Mapping
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
sys.path.insert(0, str(PACKAGE.parents[1] / 'examples'))
sys.path.insert(0, str(PACKAGE / 'src'))

# The temporary folder named before Hermes is imported. Where none is named (Linux sets no
# TMPDIR), Hermes points it into the Hermes home of the moment, which these tests delete.
for _name in ('TMPDIR', 'TMP', 'TEMP'):
    os.environ.setdefault(_name, tempfile.gettempdir())

# A Hermes home of its own, before Hermes is imported: its logging and state go there.
os.environ['HERMES_HOME'] = tempfile.mkdtemp(prefix='provared-hermes-tests-')
logging.disable(logging.CRITICAL)

from _world import offline, refused  # noqa: E402  -- the examples' guard: nothing leaves this program

import hermes_cli  # noqa: E402
from provared import arguments_fingerprint, assemble_slip, check_book, format_time, key_set_seeds, prepare_slip, to_base64url  # noqa: E402
from provared.dev import DevelopmentPasskey, development_slip  # noqa: E402
from provared.encoding import from_base64url, now_ms  # noqa: E402


def _hermes_test_module(relative):
    """A module of Hermes's own tests (not installed with Hermes), from its source."""
    path = Path(hermes_cli.__file__).resolve().parents[1] / relative
    spec = importlib.util.spec_from_file_location('_hermes_' + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fake = _hermes_test_module('tests/fakes/fake_llm_provider.py')
ToolCall, Text = fake.ToolCall, fake.Text

# Hermes reads its own version from git, and describes the computer to the
# model by starting python and pip, once, and keeps both; and on Linux Python
# starts "uname" the first time the model's client asks which processor this
# is. All done here, before the guard opens, so that no program is started
# while it is open.
import platform  # noqa: E402

from hermes_cli.version_info import get_version_info  # noqa: E402
from tools.env_probe import get_environment_probe_line  # noqa: E402

get_version_info()
get_environment_probe_line()
platform.uname().processor  # noqa: B018 -- read once on purpose, so that the answer is cached before the guard that refuses new programs starts

ORDER = 'provared.order.place'
MESSAGE = 'provared.message.send'
RUN = 'provared.code.run'
SEARCH = 'provared.data.search'
OFFICE = {'order_supplies': ORDER, 'broken_order': ORDER, 'slow_order': ORDER, 'send_message': MESSAGE}
PAPER = {'item': 'printer paper', 'quantity': 5}
NOTE = {'to': 'Sam', 'text': 'The paper is ordered.'}

# Hermes's own offline settings for its tests, and no background review of memory or skills.
OFFLINE = ('updates:\n  check: false\nmodels_dev:\n  url: http://127.0.0.1:9/api.json\n'
           'skills:\n  creation_nudge_interval: 0\nmemory:\n  nudge_interval: 0\n')
# By default Hermes hands a plugin's tools to the model behind its tool
# search, so the model calls them through "tool_call". Most tests offer them
# directly; one keeps the default.
DIRECT = 'tools:\n  tool_search:\n    enabled: "off"\n'


def sign(made, actions, limits=(), passkey=None):
    """A permission for the agent of a development slip, signed with its stand-in passkey or another."""
    passkey = passkey or made.passkey
    now = now_ms()
    prepared = prepare_slip({
        'issuer': {'name': 'Sam Example (development)', 'key': passkey.key, 'rpId': passkey.rp_id, 'origin': passkey.origin},
        'agent': {'name': 'Hermes Agent', 'keys': made.agent_keys},
        'actions': list(actions), 'limits': list(limits), 'with': [], 'requires': [], 'never': [],
        'validFrom': format_time(now - 60_000), 'validUntil': format_time(now + 3_600_000),
        'purpose': 'The tests of the Provared plugin for Hermes.',
    })
    return assemble_slip(prepared, *passkey.sign(prepared['challenge']))


def write_keys(folder, made):
    """The agent's keys of a development slip, in the folder's key file."""
    ed, ml = key_set_seeds(made.agent_private_keys)
    keys = made.agent_keys
    (folder / 'agent-keys.jwk').write_text(json.dumps({'keys': [
        {'alg': 'Ed25519', 'crv': 'Ed25519', 'kty': 'OKP', 'x': keys[0]['x'], 'd': to_base64url(ed)},
        {'alg': 'ML-DSA-87', 'kty': 'AKP', 'pub': keys[1]['pub'], 'priv': to_base64url(ml)}]}), encoding='utf-8')


class Hermes:
    """A Hermes home with the plugin installed as a folder beside the office
    plugin, a permission signed with a development stand-in for a passkey,
    and a folder of work. "others": further plugins, by name, each the code
    of its __init__.py."""

    def __init__(self, test, actions=(ORDER,), limits=(), settings=None, others=None, slip=True, direct=True):
        self.test = test
        self.direct = direct
        self.home = Path(tempfile.mkdtemp(prefix='hermes-home-'))
        self.work = Path(tempfile.mkdtemp(prefix='hermes-work-'))
        test.addCleanup(shutil.rmtree, self.home, True)
        test.addCleanup(shutil.rmtree, self.work, True)
        os.environ['HERMES_HOME'] = str(self.home)
        os.environ['OFFICE_WORLD'] = str(self.work / 'world.jsonl')
        plugin = self.home / 'plugins' / 'provared'
        plugin.mkdir(parents=True)
        for name in ('plugin.yaml', '__init__.py', 'pyproject.toml'):
            shutil.copy(PACKAGE / name, plugin / name)
        shutil.copytree(PACKAGE / 'src' / 'provared_hermes', plugin / 'src' / 'provared_hermes', ignore=shutil.ignore_patterns('__pycache__'))
        self.others = {'office': (HERE / 'office_plugin.py').read_text(encoding='utf-8'), **(others or {})}
        for name, code in self.others.items():
            other = self.home / 'plugins' / name
            other.mkdir(parents=True)
            (other / 'plugin.yaml').write_text(f'name: {name}\nversion: 0.0.1\n', encoding='utf-8')
            (other / '__init__.py').write_text(code, encoding='utf-8')
        self.settings = {'actions': OFFICE, **(settings or {})}
        self.folder = Path(self.settings.get('folder') or self.home / 'plugin-data' / 'provared')
        self.made = development_slip(actions=[RUN])
        self.issuer_keys = self.made.issuer_keys
        self.folder.mkdir(parents=True, exist_ok=True)
        write_keys(self.folder, self.made)
        if slip:
            self.place(sign(self.made, actions, limits))

    def place(self, slip):
        (self.folder / 'slip.json').write_text(json.dumps(slip), encoding='utf-8')

    def config(self):
        names = ['provared', *self.others]
        return (OFFLINE + (DIRECT if self.direct else '') + 'plugins:\n  enabled:\n' + ''.join(f'    - {n}\n' for n in names)
                + '  entries:\n    provared:\n      settings:\n' + ''.join(f'        {line}\n' for line in json.dumps(self.settings, indent=2).splitlines()))

    def run(self, script, then=None, toolsets=('office', 'todo', 'session_search')):
        """One turn with the stand-in model; "then" (a function of the agent)
        runs after it, inside the guard. Gives the turn's result."""
        from hermes_cli.plugins import get_plugin_manager
        from run_agent import AIAgent
        with fake.FakeLLMServer(list(script)) as srv:
            fake.write_hermes_home(self.home, srv.base_url, extra_config=self.config())
            get_plugin_manager().discover_and_load(force=True)
            agent = AIAgent(provider='custom', base_url=srv.base_url, api_key='sk-fake', model='fake-model',
                            session_id='provared-tests', quiet_mode=True, platform='cli', skip_memory=True,
                            enabled_toolsets=list(toolsets))
            # Hermes describes a git working folder to the model by starting
            # git there: the tools run in a folder of their own, outside any.
            here = os.getcwd()
            os.chdir(self.work)
            refused.clear()
            try:
                with offline():
                    result = agent.run_conversation('Do the work.', conversation_history=[], task_id='t')
                    if then is not None:
                        result['then'] = then(agent)
            finally:
                os.chdir(here)
                agent.close()
                get_plugin_manager().unload()
        self.test.assertEqual(refused, [])
        return result

    def world(self, kind=None):
        """What the office's tools were handed, in order."""
        path = self.work / 'world.jsonl'
        notes = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()] if path.exists() else []
        return [n['args'] for n in notes if kind is None or n['kind'] == kind]

    def book(self):
        path = self.folder / 'book.jsonl'
        return path.read_text(encoding='utf-8') if path.exists() else ''

    def check(self):
        return check_book(self.book(), issuer_keys=self.issuer_keys)

    def stubs(self):
        return [e['content'] for e in self.check()['entries'] if e['kind'] == 'stub']


def told(result):
    """What the model was handed for each tool call, in order."""
    return [m.get('content') for m in result['messages'] if m.get('role') == 'tool']


def error(answer):
    data = json.loads(answer)
    return data.get('error') if isinstance(data, dict) else None


def details(tool, args):
    return [{'name': tool, 'sha256': arguments_fingerprint(args)}]


class Records(unittest.TestCase):
    def test_a_call_inside_the_permission_runs_and_one_outside_it_does_not(self):
        hermes = Hermes(self, actions=(ORDER,))
        result = hermes.run([ToolCall('order_supplies', PAPER), ToolCall('send_message', NOTE), Text('Done.')])
        first, second = told(result)
        self.assertEqual(json.loads(first), {'ordered': 'printer paper', 'quantity': 5})
        self.assertTrue(error(second).startswith('The tool "send_message" was not run. '))
        self.assertIn(MESSAGE, error(second))
        self.assertEqual((hermes.world('order'), hermes.world('message')), ([PAPER], []))
        [stub] = hermes.stubs()
        self.assertEqual((stub['action'], stub['details']), (ORDER, details('order_supplies', PAPER)))
        summary = hermes.check()['summary']
        self.assertTrue(summary['intact'] and summary['withinSlips'])

    def test_a_tool_called_through_hermes_s_tool_search_is_recorded_as_itself(self):
        # Hermes's default: a plugin's tools are behind its tool search, and the
        # model calls them through "tool_call", which Hermes unwraps first.
        hermes = Hermes(self, direct=False)
        result = hermes.run([ToolCall('tool_call', {'calls': [{'name': 'order_supplies', 'arguments': PAPER}]}),
                             ToolCall('tool_call', {'calls': [{'name': 'send_message', 'arguments': NOTE}]}),
                             Text('Done.')])
        self.assertTrue(error(told(result)[1]).startswith('The tool "send_message" was not run. '))
        self.assertEqual((hermes.world('order'), hermes.world('message')), ([PAPER], []))
        [stub] = hermes.stubs()
        self.assertEqual((stub['action'], stub['details']), (ORDER, details('order_supplies', PAPER)))

    def test_numbers_written_as_text_are_recorded_as_the_tool_receives_them(self):
        # Hermes turns "5" into 5 by the tool's schema before the tool runs.
        hermes = Hermes(self)
        hermes.run([ToolCall('order_supplies', {'item': 'printer paper', 'quantity': '5'}), Text('Done.')])
        self.assertEqual(hermes.world('order'), [PAPER])
        self.assertEqual(hermes.stubs()[0]['details'], details('order_supplies', PAPER))

    def test_one_of_hermes_s_own_inline_tools_is_recorded_as_it_receives_its_arguments(self):
        # session_search runs inside the agent, not through Hermes's registry,
        # and Hermes reports its arguments only after the call: "3" reaches it as 3.
        hermes = Hermes(self, actions=(SEARCH,))
        hermes.run([ToolCall('session_search', {'query': 'paper', 'limit': '3'}), Text('Done.')])
        [stub] = hermes.stubs()
        self.assertEqual((stub['action'], stub['details']), (SEARCH, details('session_search', {'query': 'paper', 'limit': 3})))

    def test_a_limit_is_kept(self):
        hermes = Hermes(self, limits=[{'action': ORDER, 'count': 1}])
        result = hermes.run([ToolCall('order_supplies', PAPER), ToolCall('order_supplies', PAPER), Text('Done.')])
        self.assertTrue(error(told(result)[1]).startswith('The tool "order_supplies" was not run. '))
        self.assertEqual((len(hermes.world('order')), len(hermes.stubs())), (1, 1))
        self.assertTrue(hermes.check()['summary']['withinSlips'])

    def test_a_tool_that_fails_is_recorded_as_failed(self):
        # Hermes hands a tool's error back as a result: the call reached the
        # tool, which may have done part of its work, so it is recorded.
        hermes = Hermes(self)
        result = hermes.run([ToolCall('broken_order', PAPER), Text('Done.')])
        said = error(told(result)[0])
        self.assertIn('the supplier is closed', said)
        self.assertEqual(hermes.world('broken'), [PAPER])
        [stub] = hermes.stubs()
        self.assertEqual(stub['details'], [{'name': 'broken_order (failed)', 'sha256': arguments_fingerprint(PAPER)},
                                           {'name': 'error', 'sha256': arguments_fingerprint(said)}])

    def test_a_tool_that_is_not_recorded_runs_without_a_stub(self):
        # The model's own list of tasks is not an action in the world.
        hermes = Hermes(self)
        result = hermes.run([ToolCall('todo_list', {'todos': [{'id': '1', 'content': 'Order paper', 'status': 'pending'}]}), Text('Done.')])
        self.assertIsNone(error(told(result)[0]))
        self.assertEqual(hermes.stubs(), [])


class WhereItStands(unittest.TestCase):
    """Hermes runs its own policy, and every plugin's pre_tool_call hooks,
    inside the tool_execution middleware, after the check."""

    def test_a_call_that_hermes_blocks_after_the_check_leaves_no_stub(self):
        guard = ('def block(tool_name, **kwargs):\n'
                 '    if tool_name == "order_supplies":\n'
                 '        return {"action": "block", "message": "Blocked by the office guard."}\n'
                 'def register(ctx):\n'
                 '    ctx.register_hook("pre_tool_call", block)\n')
        hermes = Hermes(self, others={'guard': guard})
        result = hermes.run([ToolCall('order_supplies', PAPER), Text('Done.')])
        self.assertEqual(error(told(result)[0]), 'Blocked by the office guard.')
        self.assertEqual((hermes.world(), hermes.stubs()), ([], []))

    def test_arguments_changed_after_the_check_are_recorded_as_the_tool_received_them(self):
        rewriter = ('def rewrite(tool_name, args, **kwargs):\n'
                    '    if tool_name == "send_message":\n'
                    '        return {"action": "modify", "args": {"text": "Changed by another plugin."}}\n'
                    'def register(ctx):\n'
                    '    ctx.register_hook("pre_tool_call", rewrite)\n')
        hermes = Hermes(self, actions=(MESSAGE,), others={'rewriter': rewriter})
        hermes.run([ToolCall('send_message', NOTE), Text('Done.')])
        received = {'to': 'Sam', 'text': 'Changed by another plugin.'}
        self.assertEqual(hermes.world('message'), [received])
        self.assertEqual(hermes.stubs()[0]['details'], details('send_message', received))

    def test_another_middleware_after_it_stops_every_call(self):
        # Plugins load in the order of their names: "zz-after" comes after "provared".
        after = ('def wrap(next_call, args, **kwargs):\n'
                 '    return next_call(dict(args, quantity=500))\n'
                 'def register(ctx):\n'
                 '    ctx.register_middleware("tool_execution", wrap)\n')
        hermes = Hermes(self, others={'zz-after': after})
        result = hermes.run([ToolCall('order_supplies', PAPER), Text('Done.')])
        self.assertIn('must be the last tool_execution middleware', error(told(result)[0]))
        self.assertEqual((hermes.world(), hermes.stubs()), ([], []))

    def test_another_middleware_before_it_is_checked_through(self):
        before = ('def wrap(next_call, args, **kwargs):\n'
                  '    return next_call(dict(args, quantity=7))\n'
                  'def register(ctx):\n'
                  '    ctx.register_middleware("tool_execution", wrap)\n')
        hermes = Hermes(self, others={'aa-before': before})
        hermes.run([ToolCall('order_supplies', PAPER), Text('Done.')])
        received = dict(PAPER, quantity=7)
        self.assertEqual(hermes.world('order'), [received])
        self.assertEqual(hermes.stubs()[0]['details'], details('order_supplies', received))


class Nested(unittest.TestCase):
    def test_the_same_call_wrapped_twice_gives_one_stub(self):
        # AIAgent._invoke_tool, with its defaults, runs the tool_execution
        # middleware around a call and again inside it, for the same call.
        hermes = Hermes(self)
        hermes.run([Text('Nothing yet.')], then=lambda agent: agent._invoke_tool('order_supplies', PAPER, 't', 'call-direct'))
        self.assertEqual(hermes.world('order'), [PAPER])
        [stub] = hermes.stubs()
        self.assertEqual(stub['details'], details('order_supplies', PAPER))

    def test_a_call_made_from_inside_another_is_checked_and_recorded_as_itself(self):
        # As execute_code's sandbox and a subagent call tools: from inside a call.
        for tool in ('look_around', 'look_from_a_thread'):
            with self.subTest(tool=tool):
                hermes = Hermes(self, actions=(RUN, MESSAGE))
                hermes.run([ToolCall(tool, {}), Text('Done.')])
                self.assertEqual(len(hermes.world('message')), 1)
                inner, outer = hermes.stubs()
                self.assertEqual((inner['action'], inner['details'][0]['name']), (MESSAGE, 'send_message'))
                self.assertEqual((outer['action'], outer['details']), (RUN, details(tool, {})))
                self.assertTrue(hermes.check()['summary']['withinSlips'])

    def test_a_call_from_inside_another_that_the_permission_does_not_allow_is_not_run(self):
        hermes = Hermes(self, actions=(RUN,))
        result = hermes.run([ToolCall('look_around', {}), Text('Done.')])
        self.assertIn('was not run', told(result)[0])
        self.assertEqual(hermes.world('message'), [])
        [outer] = hermes.stubs()
        self.assertEqual(outer['details'][0]['name'], 'look_around (failed)')

    def test_a_call_inside_another_of_the_same_limited_action_runs_while_the_allowance_holds(self):
        # The outer call is still running, and counts against the allowance with the stubs written.
        settings = {'actions': dict(OFFICE, order_inside=ORDER)}
        hermes = Hermes(self, limits=[{'action': ORDER, 'count': 1}], settings=settings)
        result = hermes.run([ToolCall('order_inside', {}), Text('Done.')])
        self.assertIn('already running would use the rest of what the permission allows (1 in all)', told(result)[0])
        self.assertEqual((len(hermes.world('order')), len(hermes.stubs())), (1, 1))
        # With room for both, both run, and each has its stub.
        hermes = Hermes(self, limits=[{'action': ORDER, 'count': 5}], settings=settings)
        hermes.run([ToolCall('order_inside', {}), Text('Done.')])
        self.assertEqual((len(hermes.world('order')), len(hermes.stubs())), (2, 2))

    def test_calls_side_by_side(self):
        # As Hermes's executor runs a batch of calls, each in a thread of its own.
        def side_by_side(agent):
            answers = {}

            def call(name):
                answers[name] = agent._invoke_tool('slow_order', {'item': name, 'seconds': 1}, 't', name, skip_tool_execution_middleware=False)

            threads = [threading.Thread(target=call, args=(name,)) for name in ('first', 'second')]
            for t in threads:
                t.start()
            for t in threads:
                t.join(60)
            return answers

        # Room for one more of a limited action: one runs, the other is not run, and the model may make it again.
        hermes = Hermes(self, limits=[{'action': ORDER, 'count': 1}])
        answers = hermes.run([Text('Nothing yet.')], then=side_by_side)['then']
        refusals = [a for a in answers.values() if 'already running would use the rest' in a]
        self.assertEqual((len(refusals), len(hermes.world('slow')), len(hermes.stubs())), (1, 1, 1))
        # Room for both: both run, side by side, as for an action with no limit.
        for limits in ([{'action': ORDER, 'count': 5}], []):
            hermes = Hermes(self, limits=limits)
            hermes.run([Text('Nothing yet.')], then=side_by_side)
            self.assertEqual((len(hermes.world('slow')), len(hermes.stubs())), (2, 2))


@contextlib.contextmanager
def stand_in_terminal(hermes):
    """Hermes's terminal tool, its handler swapped for one that starts no shell
    and notes the command in the office's world."""
    import tools.terminal_tool  # noqa: F401  -- registers "terminal"
    from tools.registry import registry
    entry = registry.get_entry('terminal')
    original = entry.handler

    def terminal(args, **_):
        with open(hermes.work / 'world.jsonl', 'a', encoding='utf-8') as f:
            f.write(json.dumps({'kind': 'terminal', 'args': args}) + '\n')
        return json.dumps({'output': 'ok', 'exit_code': 0})

    entry.handler = terminal
    try:
        yield
    finally:
        entry.handler = original


class HermesItself(unittest.TestCase):
    """Paths of Hermes's own that the plugin meets."""

    def test_the_desktop_app_s_batch_of_terminal_commands_runs_under_the_starting_permission(self):
        # The desktop app runs the terminal commands of one turn through the middleware together.
        from provared_hermes.folder import starting_permission
        from tools import approval
        perm = starting_permission([])
        hermes = Hermes(self, actions=perm['actions'], limits=perm['limits'])
        keys = ('provared-desktop', 'provared-tests', 'default')
        os.environ['HERMES_SESSION_SOURCE'] = 'desktop'
        os.environ['HERMES_SESSION_KEY'] = 'provared-desktop'
        for key in keys:
            approval.register_gateway_notify(key, lambda data: None)
        try:
            with stand_in_terminal(hermes):
                result = hermes.run([ToolCall('terminal', {'command': 'echo one'}, parallel=[('terminal', {'command': 'echo two'})]),
                                     Text('Done.')], toolsets=('terminal',))
        finally:
            os.environ.pop('HERMES_SESSION_SOURCE', None)
            os.environ.pop('HERMES_SESSION_KEY', None)
            for key in keys:
                approval.unregister_gateway_notify(key)
        self.assertEqual([error(a) for a in told(result)], [None, None])
        self.assertEqual(sorted(a['command'] for a in hermes.world('terminal')), ['echo one', 'echo two'])
        self.assertEqual([s['action'] for s in hermes.stubs()], [RUN, RUN])

    def test_one_of_hermes_s_own_tools_that_raises_after_acting_leaves_a_failed_stub(self):
        # delegate_task, memory, session_search and other agent-level tools raise through the middleware.
        import run_agent
        hermes = Hermes(self, actions=('provared.agent.instruct',))
        original = run_agent.AIAgent._dispatch_delegate_task

        def delegate(agent, args):
            with open(hermes.work / 'world.jsonl', 'a', encoding='utf-8') as f:
                f.write(json.dumps({'kind': 'delegated', 'args': args}) + '\n')  # the subagent has been started
            raise RuntimeError('the handle could not be written back')

        run_agent.AIAgent._dispatch_delegate_task = delegate
        try:
            hermes.run([ToolCall('delegate_task', {'goal': 'Order the paper.'}), Text('Done.')], toolsets=('office', 'delegation'))
        finally:
            run_agent.AIAgent._dispatch_delegate_task = original
        self.assertEqual(len(hermes.world('delegated')), 1)
        [stub] = hermes.stubs()
        self.assertEqual(stub['details'][0]['name'], 'delegate_task (failed)')
        self.assertEqual(stub['details'][1], {'name': 'error', 'sha256': arguments_fingerprint('RuntimeError: the handle could not be written back')})

    def test_in_hermes_s_plugin_host_no_recorded_call_runs(self):
        # plugins.isolation: host runs third-party plugins in a separate local
        # Python process, which Hermes starts: the guard allows that start here,
        # and still refuses any connection.
        import _world
        hermes = Hermes(self, actions=(RUN,))
        hermes.config = (lambda base: lambda: base().replace('plugins:\n', 'plugins:\n  isolation: host\n', 1))(hermes.config)
        processes, _world._PROCESSES = _world._PROCESSES, ()
        try:
            with stand_in_terminal(hermes):
                result = hermes.run([ToolCall('terminal', {'command': 'echo hi'}), Text('Done.')], toolsets=('terminal',))
        finally:
            _world._PROCESSES = processes
        self.assertIn('plugins.isolation: in_process', error(told(result)[0]))
        self.assertEqual((hermes.world('terminal'), hermes.stubs()), ([], []))


class Folder(unittest.TestCase):
    def test_without_a_permission_no_recorded_call_runs(self):
        hermes = Hermes(self, slip=False)
        result = hermes.run([ToolCall('order_supplies', PAPER), Text('Done.')])
        self.assertIn('There is no signed permission', error(told(result)[0]))
        self.assertEqual((hermes.world(), hermes.book()), ([], ''))

    def test_a_mistake_in_the_settings_stops_every_call(self):
        hermes = Hermes(self, settings={'actions': {'order_supplies': 'Not A Name'}})
        result = hermes.run([ToolCall('order_supplies', PAPER), Text('Done.')])
        self.assertIn('The setting "actions" of the Provared plugin has a mistake', error(told(result)[0]))
        self.assertEqual(hermes.world(), [])

    def test_a_book_that_another_program_holds_records_nothing(self):
        from provared_hermes.folder import _Lock
        hermes = Hermes(self)
        lock = _Lock(hermes.folder / 'book.lock')
        self.assertTrue(lock.acquire())
        try:
            result = hermes.run([ToolCall('order_supplies', PAPER), Text('Done.')])
        finally:
            lock.release()
        self.assertIn('is held by another program', error(told(result)[0]))
        self.assertEqual(hermes.world(), [])

    def test_the_book_is_kept_between_runs_and_a_new_permission_is_taken_in(self):
        hermes = Hermes(self)
        hermes.run([ToolCall('order_supplies', PAPER), Text('Done.')])
        # A new permission from the same passkey, put in place while Hermes runs.
        hermes.place(sign(hermes.made, (ORDER, MESSAGE)))
        hermes.run([ToolCall('send_message', NOTE), Text('Done.')])
        self.assertEqual(hermes.world('message'), [NOTE])
        check = hermes.check()
        self.assertEqual((check['summary']['counts']['slips'], check['summary']['counts']['stubs']), (2, 2))
        self.assertTrue(check['summary']['intact'] and check['summary']['withinSlips'])

    def test_a_permission_from_another_passkey_is_not_taken_in(self):
        hermes = Hermes(self)

        def place_and_call(agent):
            hermes.place(sign(hermes.made, (ORDER, MESSAGE), passkey=DevelopmentPasskey()))
            return agent._invoke_tool('send_message', NOTE, 't', 'call-after')

        answer = hermes.run([ToolCall('order_supplies', PAPER), Text('Done.')], then=place_and_call)['then']
        # The permission before goes on, and it does not allow messages.
        self.assertIn('was not run', error(answer))
        self.assertEqual((len(hermes.world('order')), hermes.world('message')), (1, []))
        self.assertEqual(hermes.check()['summary']['counts']['slips'], 1)


class Commands(unittest.TestCase):
    def test_init_use_and_status(self):
        import contextlib
        import io

        from provared_hermes import cli
        with tempfile.TemporaryDirectory() as where:
            folder = Path(where) / 'agent'
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(['--folder', str(folder), 'init']), 0)
            link = next(line for line in out.getvalue().splitlines() if line.startswith('https://sign.prova.red/#permission='))
            permission = json.loads(from_base64url(link.split('=', 1)[1]).decode('utf-8'))
            keys = json.loads((folder / 'agent-keys.jwk').read_text(encoding='utf-8'))['keys']
            self.assertEqual(permission['agent']['keys'], [{'alg': 'Ed25519', 'crv': 'Ed25519', 'kty': 'OKP', 'x': keys[0]['x']},
                                                           {'alg': 'ML-DSA-87', 'kty': 'AKP', 'pub': keys[1]['pub']}])
            # A permission for those keys, signed on the page and saved.
            passkey = DevelopmentPasskey()
            made = type('Made', (), {'agent_keys': permission['agent']['keys'], 'passkey': passkey})
            saved = Path(where) / 'slip.json'
            saved.write_text(json.dumps(sign(made, (ORDER,))), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()) as said:
                self.assertEqual(cli.main(['--folder', str(folder), 'use', str(saved)]), 0)
            self.assertIn('is in place', said.getvalue())
            self.assertEqual(json.loads((folder / 'slip.json').read_text(encoding='utf-8')), json.loads(saved.read_text(encoding='utf-8')))
            # A permission for other keys is refused.
            other = Path(where) / 'other.json'
            other.write_text(json.dumps(development_slip(actions=[ORDER]).slip), encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()) as said:
                self.assertEqual(cli.main(['--folder', str(folder), 'use', str(other)]), 1)
            self.assertIn('names other keys', said.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as said:
                self.assertEqual(cli.main(['--folder', str(folder), 'status']), 0)
            self.assertIn('There is no book yet', said.getvalue())


class FailsClosed(unittest.TestCase):
    def test_a_fault_before_the_tool_is_a_refusal_not_a_pass(self):
        # Hermes runs the tool anyway when a middleware raises before it calls next_call.
        from provared_hermes import HermesRecorder

        class Faulty(Mapping):
            def __getitem__(self, key):
                raise KeyError(key)

            def __iter__(self):
                raise RuntimeError('a fault')

            def __len__(self):
                return 1

        ran = []
        with tempfile.TemporaryDirectory() as where:
            answer = HermesRecorder(where).on_tool_execution('order_supplies', Faulty(), lambda args: ran.append(args))
        self.assertEqual(ran, [])
        self.assertIn('was not run. Provared could not check it', error(answer))

    def test_on_an_older_hermes_the_plugin_loads_and_refuses_the_call_itself(self):
        # Hermes skips a plugin whose manifest rejects the version running, and the tools would then run with no check:
        # the manifest names no version, so on Hermes 0.21.6 the plugin loads, and its own check refuses the call.
        from unittest import mock
        hermes = Hermes(self, actions=(MESSAGE,))  # orders are not allowed
        with mock.patch('hermes_cli.plugins_manifest.running_hermes_version', return_value='0.21.6'):
            result = hermes.run([ToolCall('order_supplies', PAPER), Text('Done.')])
        self.assertEqual(hermes.world('order'), [])
        self.assertIn('untested_hermes', error(told(result)[0]))
        self.assertEqual(hermes.stubs(), [])


if __name__ == '__main__':
    unittest.main()
