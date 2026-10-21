# The plugin's recorder, driven directly: each tool call is handed to it as
# Hermes hands a call to a tool_execution middleware, with a next_call of the
# shape Hermes's own has (a closure over "index" inside "call_at", which
# closes over "callbacks"), the plugin's the last of the chain. Fast, and
# with no agent: test_plugin.py runs a real Hermes agent.
#
# Run from this package's folder, with its own environment:
#   .venv/Scripts/python -m unittest discover -s tests

import contextlib
import importlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'src'))

from provared import (  # noqa: E402
    arguments_fingerprint,
    assemble_cancellation,
    assemble_slip,
    check_book,
    entry_line,
    fingerprint,
    format_time,
    key_set_seeds,
    prepare_cancellation,
    prepare_slip,
    to_base64url,
)
from provared.dev import DevelopmentPasskey, development_slip  # noqa: E402
from provared.encoding import from_base64url, now_ms, parse_time  # noqa: E402

import provared_hermes  # noqa: E402
from provared_hermes import HermesRecorder, cli  # noqa: E402
from provared_hermes.commands import command_action  # noqa: E402
from provared_hermes.folder import starting_permission  # noqa: E402

ORDER = 'provared.order.place'
MESSAGE = 'provared.message.send'
READ = 'provared.data.read'
RUN = 'provared.code.run'
INSTRUCT = 'provared.agent.instruct'
OFFICE = {'order_supplies': ORDER, 'send_message': MESSAGE}
PAPER = {'item': 'printer paper', 'quantity': 5}


def chain(tool):
    """A next_call as Hermes's _run_execution_chain makes it, with this
    middleware the last of one. tool(args) is the tool."""
    callbacks = [object()]

    def call_at(index, payload):
        if index >= len(callbacks):
            return tool(payload)

        def next_call(next_payload=None):
            return call_at(index + 1, payload if next_payload is None else next_payload)
        return next_call
    return call_at(0, None)


def ok(args):
    return json.dumps({'ok': True})


def hermes_class(module, name):
    """One of Hermes's own classes, from Hermes's source installed beside these
    tests (with a Hermes home of its own where none is set yet). The temporary
    folder is named first: where none is named, Hermes points it into its home."""
    for variable in ('TMPDIR', 'TMP', 'TEMP'):
        os.environ.setdefault(variable, tempfile.gettempdir())
    os.environ.setdefault('HERMES_HOME', tempfile.mkdtemp(prefix='provared-hermes-tests-'))
    return getattr(importlib.import_module(module), name)


def sign(made, actions, limits=(), passkey=None, never=()):
    passkey = passkey or made.passkey
    now = now_ms()
    prepared = prepare_slip({
        'issuer': {'name': 'Sam Example (development)', 'key': passkey.key, 'rpId': passkey.rp_id, 'origin': passkey.origin},
        'agent': {'name': 'Hermes Agent', 'keys': made.agent_keys},
        'actions': list(actions), 'limits': list(limits), 'with': [], 'requires': [], 'never': list(never),
        'validFrom': format_time(now - 60_000), 'validUntil': format_time(now + 3_600_000),
        'purpose': 'The tests of the Provared plugin for Hermes.',
    })
    return assemble_slip(prepared, *passkey.sign(prepared['challenge']))


class Agent:
    """A folder with the agent's keys and a permission signed with a development
    stand-in for a passkey, and the plugin's recorder on it."""

    def __init__(self, test, actions=(ORDER, MESSAGE), limits=(), never=(), unknown_chain='refuse'):
        self.test = test
        self.folder = Path(tempfile.mkdtemp(prefix='provared-hermes-folder-'))
        test.addCleanup(shutil.rmtree, self.folder, True)
        self.made = development_slip(actions=[RUN])
        ed, ml = key_set_seeds(self.made.agent_private_keys)
        keys = self.made.agent_keys
        (self.folder / 'agent-keys.jwk').write_text(json.dumps({'keys': [
            {'alg': 'Ed25519', 'crv': 'Ed25519', 'kty': 'OKP', 'x': keys[0]['x'], 'd': to_base64url(ed)},
            {'alg': 'ML-DSA-87', 'kty': 'AKP', 'pub': keys[1]['pub'], 'priv': to_base64url(ml)}]}), encoding='utf-8')
        self.place(sign(self.made, actions, limits, never=never))
        self.recorder = self.new_recorder(unknown_chain)

    def new_recorder(self, unknown_chain='refuse'):
        recorder = HermesRecorder(str(self.folder), OFFICE, None, unknown_chain)
        self.test.addCleanup(recorder.close)
        return recorder

    def place(self, slip, name='slip.json'):
        path = self.folder / name
        path.write_text(json.dumps(slip), encoding='utf-8')
        return path

    def call(self, tool, args, run=ok, call_id='call-1', recorder=None):
        return (recorder or self.recorder).on_tool_execution(tool, args, chain(run), call_id)

    def book(self):
        path = self.folder / 'book.jsonl'
        return path.read_text(encoding='utf-8') if path.exists() else ''

    def check(self):
        return check_book(self.book(), issuer_keys=self.made.issuer_keys)

    def stubs(self):
        return [e['content'] for e in self.check()['entries'] if e['kind'] == 'stub']


def refused(answer):
    data = json.loads(answer)
    return isinstance(data, dict) and isinstance(data.get('error'), str) and 'was not run' in data['error']


def in_thread(work):
    out, failed = [], []

    def job():
        try:
            out.append(work())
        except BaseException as e:  # noqa: BLE001 -- handed to the test
            failed.append(e)

    thread = threading.Thread(target=job, daemon=True)
    thread.start()
    return thread, out, failed


class Raised(unittest.TestCase):
    def test_a_tool_that_raises_after_acting_leaves_a_failed_stub_and_the_error_goes_on(self):
        agent = Agent(self)
        acted = []

        def tool(args):
            acted.append(args)
            raise RuntimeError('the supplier hung up after taking the order')

        with self.assertRaises(RuntimeError):
            agent.call('order_supplies', PAPER, tool)
        [stub] = agent.stubs()
        self.assertEqual(acted, [PAPER])
        self.assertEqual(stub['details'], [{'name': 'order_supplies (failed)', 'sha256': arguments_fingerprint(PAPER)},
                                           {'name': 'error', 'sha256': arguments_fingerprint('RuntimeError: the supplier hung up after taking the order')}])

    def test_a_call_hermes_abandons_before_dispatching_it_leaves_no_stub(self):
        abandoned = hermes_class('agent.tool_executor', '_BatchAbandoned')
        agent = Agent(self)

        def tool(args):
            raise abandoned('order_supplies')

        with self.assertRaises(abandoned):
            agent.call('order_supplies', PAPER, tool)
        self.assertEqual(agent.stubs(), [])

    def test_a_tool_s_own_error_with_the_name_of_one_of_hermes_s_leaves_a_failed_stub(self):
        # "Not dispatched" is told by Hermes's own classes, not by their names: a tool that acts and then raises a class
        # of its own with the same name has acted, and its call is recorded as failed.
        for module, name in (('agent.tool_executor', '_BatchAbandoned'), ('agent.terminal_approval_batch', '_CancelledPreparation')):
            with self.subTest(name=name):
                hermes_class(module, name)  # Hermes's own is loaded, as it is while Hermes runs
                own = type(name, (Exception,), {})
                agent = Agent(self)
                acted = []

                def tool(args, own=own, acted=acted):
                    acted.append(args)
                    raise own('the tool acted first')

                with self.assertRaises(own):
                    agent.call('order_supplies', PAPER, tool)
                [stub] = agent.stubs()
                self.assertEqual(acted, [PAPER])
                self.assertEqual(stub['details'][0]['name'], 'order_supplies (failed)')

    def test_an_error_wrapped_as_hermes_wraps_one_is_unwrapped_only_from_hermes_s_own_wrapper(self):
        abandoned = hermes_class('agent.tool_executor', '_BatchAbandoned')
        wrapper = hermes_class('hermes_cli.middleware', '_DownstreamExecutionError')
        own_wrapper = type('_DownstreamExecutionError', (Exception,), {})
        for wrap, stubs in ((wrapper, 0), (own_wrapper, 1)):
            with self.subTest(wrapper=wrap):
                agent = Agent(self)

                def tool(args, wrap=wrap):
                    error = wrap('below the middleware')
                    error.original = abandoned('order_supplies')
                    raise error

                with self.assertRaises(wrap):
                    agent.call('order_supplies', PAPER, tool)
                self.assertEqual(len(agent.stubs()), stubs)


class SharedIds(unittest.TestCase):
    def test_another_call_with_the_same_tool_and_id_made_inside_a_call_is_checked_as_itself(self):
        # A nested subagent whose model service names its first call as the parent's was named.
        for other_thread in (False, True):
            with self.subTest(other_thread=other_thread):
                agent = Agent(self, actions=(INSTRUCT,), limits=[{'action': INSTRUCT, 'count': 1}])
                runs = []

                def outer(args):
                    runs.append(args)

                    def nested():
                        return agent.call('delegate_task', {'goal': 'something else'}, lambda a: runs.append(a) or ok(a), 'call_0')
                    if not other_thread:
                        return nested()
                    import contextvars
                    ctx = contextvars.copy_context()  # as Hermes's propagate_context_to_thread does
                    thread, out, failed = in_thread(lambda: ctx.run(nested))
                    thread.join(10)
                    return out[0]

                answer = agent.call('delegate_task', {'goal': 'first'}, outer, 'call_0')
                self.assertTrue(refused(answer))  # the nested call's refusal, handed back as the tool's answer
                self.assertEqual(runs, [{'goal': 'first'}])
                self.assertEqual(len(agent.stubs()), 1)

    def test_hermes_s_second_pass_over_the_same_call_gives_one_stub(self):
        agent = Agent(self)

        def outer(args):
            return agent.call('order_supplies', dict(args), ok, 'call_0')

        agent.call('order_supplies', PAPER, outer, 'call_0')
        self.assertEqual(len(agent.stubs()), 1)

    def test_reports_about_two_calls_with_one_id_go_to_their_own_call(self):
        agent = Agent(self, actions=(READ,))
        a_reported, b_started = threading.Event(), threading.Event()
        A, B = {'path': 'a.txt'}, {'path': 'b.txt'}

        def tool_a(args):
            b_started.wait(5)
            agent.recorder.on_transform_tool_result('read_file', args, 'call_0')
            a_reported.set()
            time.sleep(0.3)
            return ok(args)

        def tool_b(args):
            b_started.set()
            a_reported.wait(5)
            agent.recorder.on_transform_tool_result('read_file', args, 'call_0')
            return ok(args)

        ta = in_thread(lambda: agent.call('read_file', A, tool_a, 'call_0'))[0]
        time.sleep(0.2)
        tb = in_thread(lambda: agent.call('read_file', B, tool_b, 'call_0'))[0]
        ta.join(10)
        tb.join(10)
        self.assertEqual(sorted(s['details'][0]['sha256'] for s in agent.stubs()), sorted([arguments_fingerprint(A), arguments_fingerprint(B)]))

    def test_a_blocked_report_marks_only_its_own_call(self):
        agent = Agent(self, actions=(READ,))
        a_in, b_marked = threading.Event(), threading.Event()
        A, B = {'path': 'a.txt'}, {'path': 'b.txt'}

        def tool_a(args):
            a_in.set()
            b_marked.wait(5)
            return ok(args)

        def tool_b(args):
            a_in.wait(5)
            agent.recorder.on_post_tool_call('read_file', args, 'call_0', status='blocked')
            b_marked.set()
            return json.dumps({'error': 'blocked by a guardrail'})

        ta = in_thread(lambda: agent.call('read_file', A, tool_a, 'call_0'))[0]
        time.sleep(0.2)
        tb = in_thread(lambda: agent.call('read_file', B, tool_b, 'call_0'))[0]
        ta.join(10)
        tb.join(10)
        self.assertEqual([s['details'] for s in agent.stubs()], [[{'name': 'read_file', 'sha256': arguments_fingerprint(A)}]])

    def test_a_report_of_a_call_hermes_gave_up_on_is_not_taken_for_what_the_tool_received(self):
        # On a timeout or a stop, Hermes reports the arguments as the model gave them while the tool may still run.
        agent = Agent(self)

        def tool(args):
            agent.recorder.on_post_tool_call('order_supplies', {'item': 'printer paper', 'quantity': '5'}, 'call-1', status='timeout')
            return ok(args)

        agent.call('order_supplies', PAPER, tool)
        self.assertEqual(agent.stubs()[0]['details'][0]['sha256'], arguments_fingerprint(PAPER))


class Allowance(unittest.TestCase):
    def test_calls_from_inside_others_and_side_by_side_run_while_the_allowance_holds(self):
        perm = starting_permission([])
        self.assertEqual([lim['count'] for lim in perm['limits']], [500, 500])
        agent = Agent(self, actions=perm['actions'], limits=perm['limits'], never=perm['never'])
        ran = []

        def terminal(args):
            ran.append(args)
            return json.dumps({'output': 'ok', 'exit_code': 0})

        # execute_code's sandbox calling terminal: both provared.code.run.
        agent.call('execute_code', {'code': 'terminal("ls")'}, lambda a: agent.call('terminal', {'command': 'ls'}, terminal, ''), 'call-x')
        self.assertEqual(ran, [{'command': 'ls'}])
        # One call that hangs does not stop the others.
        release = threading.Event()
        hung = in_thread(lambda: agent.call('terminal', {'command': 'tail -f log'}, lambda a: release.wait(30) and ok(a), 'call-h'))[0]
        time.sleep(0.3)
        for tool, args in (('terminal', {'command': 'echo hi'}), ('mcp_github_create_issue', {'title': 't'}), ('browser_click', {'ref': 'e1'})):
            self.assertFalse(refused(agent.call(tool, args, ok, 'c-' + tool)), tool)
        release.set()
        hung.join(10)
        self.assertEqual(len(agent.stubs()), 6)

    def test_calls_already_running_count_against_the_allowance(self):
        agent = Agent(self, limits=[{'action': ORDER, 'count': 2}])
        release = threading.Event()
        running = [in_thread(lambda i=i: agent.call('order_supplies', dict(PAPER, item=f'item {i}'), lambda a: release.wait(10) and ok(a), f'c{i}'))[0]
                   for i in range(2)]
        time.sleep(0.4)
        answer = agent.call('order_supplies', PAPER, ok, 'c3')
        self.assertTrue(refused(answer))
        self.assertIn('already running would use the rest of what the permission allows (2 in all)', answer)
        release.set()
        for t in running:
            t.join(10)
        self.assertEqual(len(agent.stubs()), 2)
        self.assertTrue(agent.check()['summary']['withinSlips'])


class Commands(unittest.TestCase):
    def test_deletions_and_releases_are_read_in_their_common_forms(self):
        deletes = ['/bin/rm -rf work', '\\rm -rf work', 'command rm -rf work', 'find . -name "*.py" -delete', 'shred -u secrets.txt',
                   'git -c core.x=y push --force', 'python -c "import shutil; shutil.rmtree(\'work\')"', 'ri -Recurse work',
                   'rd /s /q work', 'mv work /dev/null', ': > important.db', 'sudo -u root rm -r x', 'bash -lc "rm -rf x"',
                   'node -e "require(\'fs\').rmSync(\'x\', {recursive: true})"', 'git clean -fdx', 'Remove-Item -Recurse x']
        releases = ['git -C repo push origin main', 'npx -y npm publish', 'python -m twine upload dist/*', 'gh release create v1']
        runs = ['ls -la', 'echo hello > out.txt', 'cat a.txt 2>/dev/null', 'git status', 'python -c "print(1)"', 'mv a b', 'make 2>&1 | tee log']
        self.assertEqual({c: command_action(c) for c in deletes}, {c: 'provared.data.delete' for c in deletes})
        self.assertEqual({c: command_action(c) for c in releases}, {c: 'provared.code.release' for c in releases})
        self.assertEqual({c: command_action(c) for c in runs}, {c: 'provared.code.run' for c in runs})

    def test_the_rows_shared_with_the_recorder_beside_claude_code(self):
        # The same rows stand in integrations/claude-code/test/claude-code.test.mjs, so that the two readers are held to one design.
        self.assertEqual({c: command_action(c) for c, _ in SHARED_ROWS}, {c: KIND[k] for c, k in SHARED_ROWS})

    def test_command_lines_handed_on_are_read_as_the_recorder_beside_claude_code_reads_them(self):
        # eval, iex and Invoke-Expression; each command find -exec runs; cmd /c written without a space; and \; read both ways.
        self.assertEqual({c: command_action(c) for c, _ in HANDED_ON}, {c: KIND[k] for c, k in HANDED_ON})
        # A long chain of find -exec is read part by part, in a time in step with its length.
        started = time.monotonic()
        self.assertEqual(command_action('find . ' + '-exec find . ' * 120 + '; rm -rf x'), KIND['delete'])
        self.assertLess(time.monotonic() - started, 2)

    def test_a_long_line_of_any_shape_is_read_in_a_time_in_step_with_its_length(self):
        # The shapes timed in the tests of the recorder beside Claude Code: at five times the length, the time may grow
        # about five times, not twenty-five (each once grew with the square of the length).
        def nest(inner, k):
            for _ in range(k):
                inner = 'bash -c "' + inner.replace('\\', '\\\\').replace('"', '\\"') + '"'
            return inner

        shapes = {
            'redirections': lambda n: 'a>&' * (n // 3),
            'moves': lambda n: 'x ' + 'mv a ' * (n // 5),
            'pushes': lambda n: 'git push ' * (n // 9),
            'knownWords': lambda n: 'x ' + 'git push ' * (n // 9),
            'nested': lambda n: nest('git push ' * (n // 9), 4),
            'laterShells': lambda n: 'x ' + 'sh -c "a b" ' * (n // 12),
            'handedOn': lambda n: 'x ' + 'su -c "a b" ' * (n // 12),
            'endMarks': lambda n: 'echo ' + '\\; ' * (n // 3),
            'substitutions': lambda n: 'echo "' + ' '.join(f'$(x{k})' for k in range(n // 9)) + '"',
            'pipes': lambda n: 'echo a | sh | ' * (n // 14),
        }

        def timed(line):
            started = time.perf_counter()
            command_action(line)
            return time.perf_counter() - started

        # On a busy computer one run can be slow: a line is timed again, up to three times, until a run is quick enough,
        # and the quickest counts. The longer line may also take up to two seconds whatever the shorter took, and never 20.
        def quickest(line, enough):
            best = float('inf')
            for _ in range(3):
                if best < enough:
                    break
                best = min(best, timed(line))
            return best

        for name, shape in shapes.items():
            with self.subTest(shape=name):
                small = quickest(shape(120_000), 0)
                allowed = min(max(15 * small, 2.0), 20)
                large = quickest(shape(600_000), allowed)
                self.assertLess(large, allowed, f'{small:.2f} s at 120,000 characters, {large:.2f} s at 600,000')

    def test_a_line_that_both_readings_of_a_line_holding_an_end_mark_hand_down_alike_is_read_once(self):
        # "echo \; ;" before each of three shells, one inside the other: were it read again for each reading, the
        # innermost line would be read eight times. Compared with the same line with "echo x ;", read one way only.
        def shape(mark):
            inner = f"echo {mark} ; bash -c '" + 'git push ' * (600_000 // 9) + "'"
            middle = f'echo {mark} ; bash -c "{inner}"'
            return f'echo {mark} ; bash -c "' + middle.replace('"', '`"') + '"'

        def timed(line):
            started = time.perf_counter()
            self.assertEqual(command_action(line), KIND['release'])
            return time.perf_counter() - started

        # The quickest of up to three runs counts, so that one slow run on a busy computer does not fail the test.
        once = min(timed(shape('x')), timed(shape('x')), timed(shape('x')))
        both = float('inf')
        for _ in range(3):
            if both < max(3 * once, 0.6):
                break
            both = min(both, timed(shape('\\;')))
        self.assertLess(both, max(3 * once, 0.6), f'{once:.2f} s with "echo x ;", {both:.2f} s with "echo \\; ;"')


KIND = {'delete': 'provared.data.delete', 'release': 'provared.code.release', 'run': 'provared.code.run'}

# Ordinary commands that name a program only inside a quoted message, a path, a web address or a redirection (the review of
# 14 October 2026); a command line handed to ssh; a script's own calls that delete, in a line that runs an interpreter; a move
# to the null device; a file emptied by a redirection alone; and a deletion beside a quoted message.
SHARED_ROWS = [
    ("grep -r \"git push\" docs", "run"),
    ("git commit -m \"Truncate long titles in the list\"", "run"),
    ("git commit -m \"truncate long titles\"", "run"),
    ("git commit -m \"Remove the rm calls from the build script\"", "run"),
    ("git commit -m \"Fix the del key in the editor\"", "run"),
    ("git commit -m \"Ready to npm publish next week\"", "run"),
    ("git commit -m rm", "run"),
    ("git commit --message rm", "run"),
    ("sed -i 's/rm //' notes.txt", "run"),
    ("sed -i s/rm//g notes.txt", "run"),
    ("curl -sO https://example.org/files/del", "run"),
    ("cd projects/rd && ls", "run"),
    ("echo \"Done; erase the whiteboard later\"", "run"),
    (">&2 echo \"warning: low disk\"", "run"),
    ("grep -w \"rm\" scripts/build.sh", "run"),
    ("make 2>&1 | tee build.log", "run"),
    ("make &>build.log", "run"),
    ("git log --oneline > history.txt", "run"),
    ("echo hello >> notes.txt", "run"),
    ("cat notes.txt > /dev/null", "run"),
    ("> /dev/null", "run"),
    ("python -m pytest -q", "run"),
    ("python -c \"print(1)\"", "run"),
    ("grep -rn \"os.remove(\" src", "run"),
    ("mv a.txt b.txt", "run"),
    ("docker exec web shred -u secrets.txt", "delete"),
    ("ssh host \"rm -rf /srv/data\"", "delete"),
    ("ssh -p 2222 -i key.pem host 'git push --force'", "delete"),
    ("ssh host \"git push origin main\"", "release"),
    ("python -c \"import shutil; shutil.rmtree('build')\"", "delete"),
    ("python3 -c 'import os; os.remove(\"notes.txt\")'", "delete"),
    ("node -e \"require('fs').rmSync('build', {recursive: true})\"", "delete"),
    ("python - <<'EOF'\nfrom pathlib import Path\nPath('notes.txt').unlink()\nEOF", "delete"),
    ("cat > tidy.py <<'EOF'\nimport shutil\nshutil.rmtree('build')\nEOF\npython tidy.py", "delete"),
    ("perl -e 'unlink \"notes.txt\"'", "delete"),
    ("pwsh -Command \"[System.IO.File]::Delete('notes.txt')\"", "delete"),
    ("bash -c \"python3 -c 'import os; os.remove(1)'\"", "delete"),
    ("docker exec web python -c \"import shutil; shutil.rmtree('/data')\"", "delete"),
    ("mv notes.txt /dev/null", "delete"),
    ("Move-Item notes.txt $null", "delete"),
    ("move notes.txt NUL", "delete"),
    ("docker exec web mv /data/x /dev/null", "delete"),
    (": > notes.txt", "delete"),
    ("> notes.txt", "delete"),
    ("true > notes.txt", "delete"),
    ("2>notes.txt", "delete"),
    (": 2>&1 > notes.txt", "delete"),
    ("bash -c \"> notes.txt\"", "delete"),
    ("git commit -m \"Tidy\" && rm -rf build", "delete"),
    ("uv run python -m twine upload dist/*", "release"),
    ("python -X dev -m twine upload dist/*", "release"),
    ("python -m uv publish", "release"),
    ("sudo python3 -m uv publish", "release"),
    # A later word written as a program's path (the review of 15 October 2026, finding 1)
    ("docker exec c /bin/rm -rf /data", "delete"),
    ("kubectl exec p -- /bin/rm -rf x", "delete"),
    ("strace /bin/rm x", "delete"),
    ("wsl /bin/rm x", "delete"),
    ("docker exec c \\rm x", "delete"),
    ("docker exec c C:\\Tools\\rm.exe x", "delete"),
    ("docker exec c C:/Tools/shred x", "delete"),
    ("npx ./node_modules/.bin/npm publish", "release"),
    ("docker exec c ~/bin/rm x", "delete"),
    ("uv run /usr/bin/python -m twine check dist/*", "run"),
    ("uv run /usr/bin/python -m npm publish", "release"),
    ("ls docs/rm notes/del", "run"),
    # A later word that names a shell, eval, ssh, watch or parallel starts a command, read one level down (finding 2)
    ("docker exec c sh -c \"cd /; rm -rf x\"", "delete"),
    ("kubectl exec p -- bash -lc \"cd /tmp && rm -rf x\"", "delete"),
    ("docker exec c bash -c \"git push --force\"", "delete"),
    ("docker run --rm img sh -c \"x; git push\"", "release"),
    ("wsl -e sh -c \"x; rm y\"", "delete"),
    ("kubectl exec p -- ssh host \"rm -rf x\"", "delete"),
    ("docker exec c eval \"rm x\"", "delete"),
    ("docker exec c fish -c \"rm x\"", "delete"),
    ("docker exec c ksh -c \"rm x\"", "delete"),
    ("docker exec c sh -c \"ls -la\"", "run"),
    # A value in quotation marks after -c, --command, -Command or -ArgumentList, or after env -S; the words after watch and parallel (finding 3)
    ("su -c \"cd /; rm x\"", "delete"),
    ("su root -c \"rm x\"", "delete"),
    ("su --command=\"rm x\"", "delete"),
    ("script -qc \"true; rm -rf x\" /dev/null", "delete"),
    ("flock /tmp/l -c \"x; rm y\"", "delete"),
    ("watch \"x; rm y\"", "delete"),
    ("watch -n 5 \"git push\"", "release"),
    ("parallel \"rm {}\" ::: a b", "delete"),
    ("Start-Process cmd -ArgumentList '/c del x'", "delete"),
    ("Start-Process powershell -ArgumentList \"-Command git push --force\"", "delete"),
    ("Start-Process powershell -ArgumentList \"-Command 'git' push --force\"", "delete"),
    ("Start-Process -FilePath powershell -ArgumentList \"-Command 'rm' x\"", "delete"),
    ("env -S \"rm -rf x\"", "delete"),
    ("pwsh -NoProfile -Command \"`\"/usr/bin/rm`\" -rf x\"", "delete"),
    ("echo `\"rm\" -rf x`", "delete"),
    ("python -c \"import subprocess; subprocess.run(['git', 'push'])\"", "release"),
    ("python -c \"import subprocess; subprocess.run('rm -rf x', shell=True)\"", "delete"),
    ("grep -c \"rm -rf\" scripts/build.sh", "run"),
    ("git -c \"core.pager=rm\" log", "run"),
    ("python -c \"print('rm')\"", "run"),
    ("ssh -c aes128-ctr host ls", "run"),
    ("curl -c \"cookies.txt\" https://example.org", "run"),
    # A program's name in quotation marks where a program is expected, after a program that runs another (finding 4)
    ("docker exec c \"rm\" x", "delete"),
    ("kubectl exec p -- \"rm\" -rf x", "delete"),
    ("runuser -u x -- \"rm\" y", "delete"),
    ("npx \"npm\" publish", "release"),
    ("python -m \"twine\" upload dist/*", "release"),
    ("strace -f 'rm' x", "delete"),
    ("docker exec c r\"\"m x", "delete"),
    ("docker exec c \"/bin/rm\" x", "delete"),
    ("echo \"rm\"", "run"),
    ("sudo grep -w \"rm\" scripts/build.sh", "run"),
    ("docker exec c grep -w \"rm\" scripts/build.sh", "run"),
    ("docker exec c git commit -m \"rm\"", "run"),
    # The value of -m is a message only after a program whose -m takes one (finding 5)
    ("nsenter -t 1 -m shred x", "delete"),
    ("docker exec web nsenter -t 1 -m shred x", "delete"),
    ("hg commit -m rm", "run"),
    ("sudo hg commit -m rm", "run"),
    ("docker commit c img -m rm", "run"),
    ("ls | xargs -i sh -c \"rm {}\"", "delete"),
    # The first reading alone reads a program named by a path inside a word: sudo -h and xargs -i take no value.
    ("ls | xargs -i bin/rm {}", "delete"),
    ("sudo -h bin/rm x", "delete"),
    # DROP TABLE or DROP DATABASE anywhere in the text (finding 6)
    ("psql -c \"DROP TABLE users\"", "delete"),
    ("sqlite3 app.db \"drop table users\"", "delete"),
    ("mysql -e \"DROP DATABASE shop\"", "delete"),
    # A command line inside "..." that a shell runs there, $( ... ) or `...` (the re-check of 16 October 2026, finding 1)
    ("echo \"$(rm -rf x)\"", "delete"),
    ("echo \"`rm -rf x`\"", "delete"),
    ("git commit -m \"$(rm -rf x)\"", "delete"),
    ("x=\"$(git push --force)\"", "delete"),
    ("echo \"result: $(npm publish)\"", "release"),
    ("printf \"%s\" \"$(Remove-Item x)\"", "delete"),
    ("echo \"a $(echo b; rm c) d\"", "delete"),
    ("\"$(which rm)\" x", "delete"),
    ("echo '$(rm -rf x)'", "run"),
    ("echo \"today: $(date)\"", "run"),
    # Text piped or handed into a shell, and -ArgumentList written as a list (finding 4)
    ("echo \"rm -rf x\" | sh", "delete"),
    ("printf 'rm -rf x\\n' | bash", "delete"),
    ("bash <<< \"rm -rf x\"", "delete"),
    ("bash <<<\"git push\"", "release"),
    ("cat notes.txt | sh script.sh", "run"),
    ("echo \"rm -rf x\" || sh", "run"),
    ("Start-Process -FilePath cmd.exe -ArgumentList \"/c\",\"del x\"", "delete"),
    # More programs that publish or delete (finding 4)
    ("hub push", "release"),
    ("hatch publish", "release"),
    ("flit publish", "release"),
    ("pdm publish", "release"),
    ("dotnet nuget push x.nupkg", "release"),
    ("gem push x.gem", "release"),
    ("gem yank x", "delete"),
    ("helm push x.tgz oci://example", "release"),
    ("vsce publish", "release"),
    ("docker buildx build --push .", "release"),
    ("docker build -t x .", "run"),
    ("rsync -a --delete src/ dst/", "delete"),
    ("rsync -a src/ dst/", "run"),
    ("cp /dev/null x", "delete"),
    ("cp x /dev/null", "run"),
    ("sqlite3 db \"DELETE FROM x\"", "delete"),
    ("mysql shop -e \"delete from users where id = 1\"", "delete"),
    ("grep -rn \"DELETE FROM\" src", "run"),
    ("redis-cli FLUSHALL", "delete"),
    ("redis-cli GET x", "run"),
    # A quotation mark inside $( ... ) inside "..." does not close it, and \$, \` and \\ are plain inside "..." (the third check of 16 October 2026)
    ("echo \"$(echo \"$(rm -rf x)\")\"", "delete"),
    ("echo \"$(cd \"/tmp\"; rm -rf x)\"", "delete"),
    ("echo \"$(echo \")\" ; rm -rf x)\"", "delete"),
    ("echo \"$(rm -rf x\"", "delete"),
    ("echo \"$( (cd /; rm x) )\"", "delete"),
    ("echo \"$((1 + 2))\"", "run"),
    ("echo \"$(( $(rm -rf x) + 1 ))\"", "delete"),
    ("echo \"${HOME}/rm\"", "run"),
    ("echo \"${x:-$(rm -rf x)}\"", "delete"),
    ("echo \"a `echo b` $(rm c)\"", "delete"),
    ("Write-Output \"`$(Remove-Item x)\"", "delete"),
    ("Write-Output \"a `\" $(Remove-Item x)\"", "delete"),
    ("echo \"$(printf '%s' \"$(rm x)\")\"", "delete"),
    ("echo \"it's $(rm x)\"", "delete"),
    ("echo '\"$(rm x)\"'", "run"),
    ("echo \"$(echo \"$(echo \"$(echo \"$(echo \"$(echo \"$(echo \"$(rm x)\")\")\")\")\")\")\"", "delete"),
    ("echo \"\\$(rm -rf x)\"", "run"),
    ("echo \"\\`rm -rf x\\`\"", "run"),
    ("grep -rn \"\\$(rm\" docs", "run"),
    ("gh issue comment 5 --body \"Use \\`rm\\` with care\"", "run"),
    ("echo \"a\\\\$(rm x)\"", "delete"),
    ("bash -c \"echo \\\"\\$(rm -rf x)\\\"\"", "delete"),
    ("echo \"rm -rf x\" | sh -s", "delete"),
    ("printf \"rm x\" | bash -e", "delete"),
    ("echo \"$(echo ')' ; rm -rf x)\"", "delete"),
    ("echo \"$(echo \\) ; rm -rf x)\"", "delete"),
    ("echo \"$(echo '\"' ; rm -rf x)\"", "delete"),
    ("echo \"a `echo \\` ; rm -rf x`\"", "delete"),
    ("echo \"$(echo $((1 + 2)) ; rm -rf x)\"", "delete"),
    # Inside a $( ... ) in "...": a case's patterns close nothing until its esac, and a # comment runs to the end of its line (the fourth check of 16 October 2026)
    ("echo \"$(case x in a) rm -rf y;; esac)\"", "delete"),
    ("echo \"$(case x in (a) rm -rf y;; esac)\"", "delete"),
    ("echo \"$(if true; then case x in a) rm -rf y;; esac; fi)\"", "delete"),
    ("echo \"$(case x in a) case y in b) rm -rf z;; esac;; esac)\"", "delete"),
    ("echo \"$(case x in a) echo b;; esac) rm the old files\"", "run"),
    ("echo \"$(case x in (a) echo b;; esac) rm the old files\"", "run"),
    ("echo \"$(echo case) rm the old files\"", "run"),
    ("echo \"$(echo esac) $(case x in a) echo b;; esac) rm the old files\"", "run"),
    ("echo \"$(date) rm the old files\"", "run"),
    ("echo \"$(echo a # )\nrm -rf y)\"", "delete"),
    ("echo \"$(# )\nrm -rf y)\"", "delete"),
    ("echo \"$(echo a;# )\nrm -rf y)\"", "delete"),
    ("echo \"$(echo a#b) rm the old files\"", "run"),
    ("echo \"$(echo ${#x}) rm the old files\"", "run"),
    ("echo \"$(echo $#) rm the old files\"", "run"),
    ("echo \"$(echo case x) rm the old files\"", "run"),
    ("echo \"$(grep -c case x) rm the old files\"", "run"),
    ("Write-Output \"$(<# ) #> Remove-Item x)\"", "delete"),
    ("Write-Output \"$(<# ) \" #> Remove-Item x)\"", "delete"),
    ("Write-Output \"$(<# ) #>\" ; Remove-Item x", "delete"),
    ("Write-Output \"$(<# note #>) rm the old files\"", "run"),
    ("Write-Output \"$(<# note #> Get-Date) rm the old files\"", "run"),
    ("Write-Output \"$(<# ) Remove-Item x)\"", "run"),
    ("Write-Output \"$(<# a #) #> Remove-Item x)\"", "delete"),
    ("Write-Output \"$(<# a#b ) #> Remove-Item x)\"", "delete"),
]

# Rows of integrations/claude-code/test/claude-code.test.mjs for the rules added there on 13 and 14 October 2026.
HANDED_ON = [
    ('eval "rm -rf x"', 'delete'),
    ("iex 'rm -r x'", 'delete'),
    ("Invoke-Expression -Command 'Remove-Item x'", 'delete'),
    ("find . -name '*.log' -exec sh -c 'rm \"$1\"' _ {} \\;", 'delete'),
    ('cmd /c"del x"', 'delete'),
    ('Write-Output \\; cmd /c "del /q build"', 'delete'),
    ('Write-Output \\; powershell -Command "rm -r build"', 'delete'),
    ('Write-Output \\; iex "rm -r build"', 'delete'),
    ("Write-Output \\; bash -c 'rm -rf build'", 'delete'),
    ('find . -exec find . -exec rm {} \\; \\;', 'delete'),
    ("find . -exec cat {} \\; -exec sh -c 'rm \"$1\"' _ {} \\;", 'delete'),
    ('eval "git push origin main"', 'release'),
    ('find . -exec bash -c "git push" \\;', 'release'),
    ('eval "echo hi"', 'run'),
    ("iex 'Get-ChildItem'", 'run'),
    ('find . -exec sh -c "cat x" \\;', 'run'),
    ('cmd /c"dir"', 'run'),
]


class Chain(unittest.TestCase):
    def test_where_the_chain_cannot_be_read_no_recorded_call_runs_unless_the_setting_says_so(self):
        got = []

        def after(args):  # not Hermes's shape: what follows the plugin cannot be told, and here it changes the call
            got.append(dict(args, quantity=500))
            return ok(args)

        agent = Agent(self)
        answer = agent.recorder.on_tool_execution('order_supplies', PAPER, after, 'call-1')
        self.assertIn('cannot read Hermes\'s chain', answer)
        self.assertEqual((got, agent.stubs()), ([], []))
        agent = Agent(self, unknown_chain='run')
        agent.recorder.on_tool_execution('order_supplies', PAPER, after, 'call-1')
        self.assertEqual(len(got), 1)

    def test_in_hermes_s_plugin_host_no_recorded_call_runs(self):
        agent = Agent(self)
        os.environ['HERMES_PLUGIN_HOST_PROCESS'] = '1'
        try:
            answer = agent.call('order_supplies', PAPER)
        finally:
            del os.environ['HERMES_PLUGIN_HOST_PROCESS']
        self.assertIn('plugins.isolation: in_process', answer)
        # Hermes's plugin host hands the middleware a placeholder in the place of next_call.
        self.assertIn('plugins.isolation: in_process', agent.recorder.on_tool_execution('order_supplies', PAPER, object(), 'call-2'))
        self.assertEqual(agent.stubs(), [])


class Dates(unittest.TestCase):
    def test_a_stub_is_dated_when_its_call_started(self):
        agent = Agent(self)
        before = now_ms()
        agent.call('order_supplies', PAPER, lambda a: time.sleep(2.2) or ok(a))
        [stub] = agent.stubs()
        self.assertLessEqual(parse_time(stub['when']), before + 1000)


class Reload(unittest.TestCase):
    def test_a_call_running_when_the_plugin_is_unloaded_keeps_its_writer_and_its_stub(self):
        agent = Agent(self)
        release = threading.Event()
        first = in_thread(lambda: agent.call('order_supplies', PAPER, lambda a: release.wait(10) and ok(a), 'old'))[0]
        time.sleep(0.4)
        agent.recorder.close()  # Hermes unloads the plugin and loads it again
        self.assertIn('was unloaded', agent.call('order_supplies', PAPER, ok, 'late'))
        again = agent.new_recorder()
        answer = agent.call('send_message', {'to': 'Sam', 'text': 'hello'}, ok, 'new', recorder=again)
        self.assertIn('held by another program', answer)  # the book stays with the old writer while its call runs
        kept = agent.recorder._closing
        self.assertFalse(kept.closed)
        release.set()
        first.join(10)
        self.assertTrue(kept.closed)  # let go, by the plugin itself, once the call has ended
        self.assertIsNone(agent.recorder._closing)
        self.assertFalse(refused(agent.call('send_message', {'to': 'Sam', 'text': 'hello'}, ok, 'new2', recorder=again)))
        check = agent.check()
        self.assertTrue(check['summary']['intact'])
        self.assertEqual([s['action'] for s in agent.stubs()], [ORDER, MESSAGE])

    def test_a_book_another_program_changed_is_not_written_over(self):
        agent = Agent(self)
        agent.call('order_supplies', PAPER)
        with open(agent.folder / 'book.jsonl', 'ab') as f:
            f.write(b'{"not": "a line this plugin wrote"}\n')
        answer = agent.call('order_supplies', PAPER, ok, 'call-2')
        self.assertTrue(refused(answer))
        self.assertTrue(agent.book().endswith('{"not": "a line this plugin wrote"}\n'))


class Permissions(unittest.TestCase):
    def use(self, agent, slip, *flags):
        path = agent.place(slip, f'given-{time.monotonic_ns()}.json')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli.main(['--folder', str(agent.folder), 'use', str(path), *flags])
        return code, err.getvalue()

    def test_an_earlier_wider_permission_put_back_is_not_taken(self):
        agent = Agent(self)
        (agent.folder / 'slip.json').write_text('', encoding='utf-8')
        self.assertEqual(self.use(agent, sign(agent.made, (ORDER, MESSAGE)))[0], 0)
        self.assertFalse(refused(agent.call('send_message', {'to': 'Sam', 'text': 'one'})))
        wide = (agent.folder / 'slip.json').read_text(encoding='utf-8')
        self.assertEqual(self.use(agent, sign(agent.made, (ORDER,)))[0], 0)  # the person narrows it
        self.assertTrue(refused(agent.call('send_message', {'to': 'Sam', 'text': 'two'}, ok, 'c2')))
        (agent.folder / 'slip.json').write_text(wide, encoding='utf-8')  # what the agent's own write_file can do
        answer = agent.call('send_message', {'to': 'Sam', 'text': 'three'}, ok, 'c3')
        self.assertIn('an earlier one of the book', answer)
        code, err = self.use(agent, json.loads(wide))
        self.assertEqual(code, 1)
        self.assertIn('earlier one of the book', err)

    def test_a_permission_taken_away_stops_the_agent(self):
        agent = Agent(self)
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        (agent.folder / 'slip.json').write_text('', encoding='utf-8')
        self.assertTrue(refused(agent.call('order_supplies', PAPER, ok, 'c2')))
        self.assertEqual(len(agent.stubs()), 1)

    def test_a_signed_cancellation_stops_the_agent_and_goes_into_the_book(self):
        agent = Agent(self)
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        slip_fp = agent.check()['entries'][0]['fingerprint']
        prepared = prepare_cancellation({'slip': slip_fp})
        cancellation = assemble_cancellation(prepared, *agent.made.passkey.sign(prepared['challenge']))
        given = agent.place({'cancellation': cancellation}, 'cancellation-given.json')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--folder', str(agent.folder), 'cancel', str(given)]), 0)
        self.assertTrue(refused(agent.call('order_supplies', PAPER, ok, 'c2')))
        kinds = [e['kind'] for e in agent.check()['entries']]
        self.assertEqual(kinds, ['slip', 'stub', 'cancellation', 'acknowledgement'])

    def test_a_permission_from_a_passkey_never_used_is_not_taken_into_an_emptied_book(self):
        agent = Agent(self)
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        trusted = json.loads((agent.folder / 'trusted-passkeys.json').read_text(encoding='utf-8'))['passkeys']
        self.assertEqual(trusted, agent.made.issuer_keys)
        agent.recorder.close()
        (agent.folder / 'book.jsonl').write_text('', encoding='utf-8')
        agent.place(sign(agent.made, (ORDER, MESSAGE), passkey=DevelopmentPasskey()))
        answer = agent.call('send_message', {'to': 'Sam', 'text': 'hello'}, ok, 'c2', recorder=agent.new_recorder())
        self.assertIn('The permission in place (slip.json) is signed by a passkey', answer)
        self.assertIn('not on the list of passkeys this plugin trusts', answer)
        self.assertEqual(agent.book(), '')

    def test_a_new_passkey_is_taken_only_when_the_person_says_so(self):
        agent = Agent(self)
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        other = sign(agent.made, (ORDER, MESSAGE), passkey=DevelopmentPasskey())
        code, err = self.use(agent, other)
        self.assertEqual(code, 1)
        self.assertIn('--new-passkey', err)
        self.assertEqual(self.use(agent, other, '--new-passkey')[0], 0)
        self.assertFalse(refused(agent.call('send_message', {'to': 'Sam', 'text': 'hello'}, ok, 'c2')))
        with contextlib.redirect_stdout(io.StringIO()) as said:
            cli.main(['--folder', str(agent.folder), 'status'])
        self.assertIn('Intact, against the passkeys on the list, as far as this device can check: yes', said.getvalue())

    def test_a_permission_never_taken_into_the_book_is_not_kept_beside_it(self):
        agent = Agent(self)  # slip.json is in place, and no call has taken it into the book
        first = json.loads((agent.folder / 'slip.json').read_text(encoding='utf-8'))
        second = sign(agent.made, (ORDER, MESSAGE))
        self.assertEqual(self.use(agent, second)[0], 0)
        self.assertEqual(sorted(p.name for p in agent.folder.glob('slip-*.json')), [])
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))  # the book now holds the second
        self.assertEqual(self.use(agent, sign(agent.made, (ORDER,)))[0], 0)
        kept = sorted(p.name for p in agent.folder.glob('slip-*.json'))
        self.assertEqual(kept, [f"slip-{from_slip(second)}.json"])
        self.assertNotIn(f'slip-{from_slip(first)}.json', kept)

    def test_with_no_list_a_book_and_a_permission_from_two_passkeys_are_not_taken(self):
        agent = Agent(self)
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        agent.recorder.close()
        (agent.folder / 'trusted-passkeys.json').unlink()  # the list gone: what a program that edits the folder can do
        agent.place(sign(agent.made, (ORDER, MESSAGE), passkey=DevelopmentPasskey()))
        answer = agent.call('send_message', {'to': 'Sam', 'text': 'hello'}, ok, 'c2', recorder=agent.new_recorder())
        self.assertIn('hold permissions signed by 2 passkeys', answer)
        self.assertFalse((agent.folder / 'trusted-passkeys.json').exists())

    def test_a_book_holding_a_permission_from_a_passkey_not_on_the_list_is_not_taken(self):
        agent = Agent(self)
        own = json.loads((agent.folder / 'slip.json').read_text(encoding='utf-8'))
        other = sign(agent.made, (ORDER, MESSAGE), passkey=DevelopmentPasskey())
        (agent.folder / 'book.jsonl').write_text(entry_line({'slip': other}) + '\n' + entry_line({'slip': own}) + '\n', encoding='utf-8')
        (agent.folder / 'trusted-passkeys.json').write_text(json.dumps({'passkeys': agent.made.issuer_keys}), encoding='utf-8')
        answer = agent.call('order_supplies', PAPER)
        self.assertIn('The book holds a permission signed by a passkey that is not on the list', answer)

    def test_use_with_no_list_refuses_a_book_whose_permissions_come_from_two_passkeys(self):
        agent = Agent(self)
        own = json.loads((agent.folder / 'slip.json').read_text(encoding='utf-8'))
        other = sign(agent.made, (ORDER, MESSAGE), passkey=DevelopmentPasskey())
        (agent.folder / 'book.jsonl').write_text(entry_line({'slip': other}) + '\n' + entry_line({'slip': own}) + '\n', encoding='utf-8')
        code, err = self.use(agent, sign(agent.made, (ORDER,)))
        self.assertEqual(code, 1)
        self.assertIn('The book holds permissions signed by 2 passkeys', err)
        self.assertFalse((agent.folder / 'trusted-passkeys.json').exists())


def from_slip(slip):
    return fingerprint(from_base64url(slip['payload']))


class Versions(unittest.TestCase):
    """Hermes skips a plugin whose requires_hermes rejects the running version,
    and its tools then run unchecked: the manifest states no version, and the
    plugin itself refuses every recorded call on a Hermes it was not made
    for, older or newer, unless its setting untested_hermes is "run"."""

    def registered(self, agent, version, **settings):
        context = FakeContext(dict({'folder': str(agent.folder), 'actions': OFFICE}, **settings))
        from unittest import mock
        with mock.patch('hermes_cli.plugins_manifest.running_hermes_version', side_effect=version if callable(version) else None,
                        return_value=version):
            recorder = provared_hermes.register(context)
        self.addCleanup(recorder.close)
        return recorder

    def test_the_manifest_lets_any_hermes_load_the_plugin(self):
        from unittest import mock

        from hermes_cli.plugins_manifest import requires_hermes_error
        from utils import fast_safe_load
        for name in ('plugin.yaml', 'catalog-entry.yaml'):
            manifest = fast_safe_load((HERE.parent / name).read_text(encoding='utf-8'))
            self.assertNotIn('requires_hermes', manifest, name)
            for running in ('0.19.0', '0.21.6', '0.21.7', '0.22.0', '1.0.0'):
                with mock.patch('hermes_cli.plugins_manifest.running_hermes_version', return_value=running):
                    self.assertIsNone(requires_hermes_error(manifest), (name, running))

    def test_on_a_hermes_it_was_not_made_for_no_recorded_call_runs_unless_the_setting_says_so(self):
        for version in ('0.22.0', '0.23.1', '1.0.0', '0.21.6', 'nightly'):
            with self.subTest(version=version):
                agent = Agent(self)
                answer = agent.call('order_supplies', PAPER, recorder=self.registered(agent, version))
                self.assertIn('untested_hermes', answer)
                self.assertTrue(refused(answer))
                self.assertEqual(agent.stubs(), [])

        def cannot_tell():
            raise RuntimeError('no version here')

        agent = Agent(self)
        self.assertIn('cannot tell which version of Hermes', agent.call('order_supplies', PAPER, recorder=self.registered(agent, cannot_tell)))
        for version in ('0.21.7', '0.21.12'):
            agent = Agent(self)
            self.assertFalse(refused(agent.call('order_supplies', PAPER, recorder=self.registered(agent, version))), version)
        agent = Agent(self)
        recorder = self.registered(agent, '0.22.0', untested_hermes='run')  # and says so in Hermes's log
        self.assertFalse(refused(agent.call('order_supplies', PAPER, recorder=recorder)))
        agent = Agent(self)
        answer = agent.call('order_supplies', PAPER, recorder=self.registered(agent, '0.21.7', untested_hermes='yes'))
        self.assertIn('"untested_hermes" of the Provared plugin must be "refuse" or "run"', json.loads(answer)['error'])


class FakeContext:
    """What register() is handed, as Hermes's plugin context offers it."""

    def __init__(self, settings):
        self.settings = settings

    def get_config(self, name):
        return self.settings.get(name)

    def register_middleware(self, kind, callback):
        pass

    def register_hook(self, name, callback):
        pass

    def register_cli_command(self, **_):
        pass

    def on_unload(self, callback):
        pass


class BookFile(unittest.TestCase):
    def test_a_stub_the_file_did_not_take_is_written_when_the_permission_changes(self):
        agent = Agent(self)
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        real_open = open
        failures = [1]

        def full_disk(path, mode='r', *args, **kwargs):
            if mode == 'ab' and Path(path).name == 'book.jsonl' and failures[0]:
                failures[0] -= 1
                raise OSError(28, 'No space left on device')
            return real_open(path, mode, *args, **kwargs)

        from unittest import mock
        with mock.patch('provared_hermes.folder.open', full_disk, create=True):
            self.assertFalse(refused(agent.call('order_supplies', dict(PAPER, quantity=6), ok, 'c2')))
        self.assertEqual(failures, [0])
        self.assertEqual(len(agent.stubs()), 1)  # the file did not take the second stub
        Permissions.use(self, agent, sign(agent.made, (ORDER, MESSAGE)))  # the person puts a new permission in place
        self.assertFalse(refused(agent.call('send_message', {'to': 'Sam', 'text': 'hello'}, ok, 'c3')))
        self.assertTrue(agent.check()['summary']['intact'])
        self.assertEqual([s['action'] for s in agent.stubs()], [ORDER, ORDER, MESSAGE])

    def test_a_book_another_program_changed_stops_the_plugin_when_the_permission_changes(self):
        agent = Agent(self)
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        with open(agent.folder / 'book.jsonl', 'ab') as f:
            f.write(b'{"not": "a line this plugin wrote"}\n')
        Permissions.use(self, agent, sign(agent.made, (ORDER, MESSAGE)))
        for call_id in ('c2', 'c3'):
            answer = agent.call('send_message', {'to': 'Sam', 'text': 'hello'}, ok, call_id)
            self.assertIn('is not what this process wrote', answer)
            self.assertIn('until Hermes is started again', answer)
        self.assertTrue(agent.book().endswith('{"not": "a line this plugin wrote"}\n'))

    def test_a_cancellation_with_a_faulty_time_stamp_beside_it_still_stops_the_agent_and_goes_into_the_book(self):
        agent = Agent(self)
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        slip_fp = agent.check()['entries'][0]['fingerprint']
        prepared = prepare_cancellation({'slip': slip_fp})
        cancellation = assemble_cancellation(prepared, *agent.made.passkey.sign(prepared['challenge']))
        (agent.folder / 'cancellation.json').write_text(json.dumps({'cancellation': cancellation, 'stamps': 'not a list'}), encoding='utf-8')
        answer = agent.call('order_supplies', PAPER, ok, 'c2')
        self.assertTrue(refused(answer))
        self.assertNotIn('cannot be opened', answer)
        kinds = [e['kind'] for e in agent.check()['entries']]
        self.assertEqual(kinds[:3], ['slip', 'stub', 'cancellation'])

    def test_a_cancellation_that_does_not_pass_its_check_stops_every_call_until_it_is_taken_away(self):
        agent = Agent(self)
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        slip_fp = agent.check()['entries'][0]['fingerprint']
        prepared = prepare_cancellation({'slip': slip_fp})
        for name, passkey in (('another passkey', DevelopmentPasskey()), ('a spoiled signature', agent.made.passkey)):
            with self.subTest(name):
                cancellation = assemble_cancellation(prepared, *passkey.sign(prepared['challenge']))
                if name == 'a spoiled signature':
                    first = cancellation['signatures'][0]
                    first['signature'] = ('A' if first['signature'][0] != 'A' else 'B') + first['signature'][1:]
                (agent.folder / 'cancellation.json').write_text(json.dumps({'cancellation': cancellation}), encoding='utf-8')
                answer = agent.call('order_supplies', PAPER, ok, f'c-{name}')
                self.assertIn('does not pass its check', answer)
                self.assertIn('until it is put right or taken away', answer)
                (agent.folder / 'cancellation.json').unlink()
        self.assertFalse(refused(agent.call('order_supplies', PAPER, ok, 'c-after')))
        self.assertEqual([e['kind'] for e in agent.check()['entries']], ['slip', 'stub', 'stub'])


class Rules(unittest.TestCase):
    """Rules that no test held until the review of 14 October 2026."""

    def test_stubs_already_written_count_with_the_calls_running(self):
        agent = Agent(self, limits=[{'action': ORDER, 'count': 2}])
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        release = threading.Event()
        running = in_thread(lambda: agent.call('order_supplies', dict(PAPER, quantity=6), lambda a: release.wait(10) and ok(a), 'c2'))[0]
        time.sleep(0.4)
        answer = agent.call('order_supplies', dict(PAPER, quantity=7), ok, 'c3')
        release.set()
        running.join(10)
        self.assertIn('already running would use the rest of what the permission allows (2 in all)', answer)
        self.assertEqual(len(agent.stubs()), 2)
        self.assertTrue(agent.check()['summary']['withinSlips'])

    def test_stubs_older_than_the_limit_s_period_do_not_count(self):
        agent = Agent(self, limits=[{'action': ORDER, 'count': 2, 'per': 1}])
        self.assertFalse(refused(agent.call('order_supplies', PAPER)))
        time.sleep(1.3)
        release = threading.Event()
        running = in_thread(lambda: agent.call('order_supplies', dict(PAPER, quantity=6), lambda a: release.wait(10) and ok(a), 'c2'))[0]
        time.sleep(0.3)
        answer = agent.call('order_supplies', dict(PAPER, quantity=7), ok, 'c3')
        release.set()
        running.join(10)
        self.assertFalse(refused(answer), answer)
        self.assertEqual(len(agent.stubs()), 3)
        self.assertTrue(agent.check()['summary']['withinSlips'])

    def test_only_one_second_pass_in_the_same_thread_with_the_same_arguments_is_let_through(self):
        goal = {'goal': 'the same'}
        for case in ('twice in the same thread', 'from another thread'):
            with self.subTest(case=case):
                agent = Agent(self, actions=(INSTRUCT,), limits=[{'action': INSTRUCT, 'count': 1}])
                runs, answers = [], []

                def inner():
                    return agent.call('delegate_task', dict(goal), lambda a: runs.append(a) or ok(a), 'call_0')

                def outer(args):
                    if case == 'twice in the same thread':
                        answers.append(inner())
                        answers.append(inner())
                    else:
                        import contextvars
                        ctx = contextvars.copy_context()  # as Hermes's propagate_context_to_thread does
                        thread, out, _ = in_thread(lambda: ctx.run(inner))
                        thread.join(10)
                        answers.append(out[0])
                    return ok(args)

                agent.call('delegate_task', dict(goal), outer, 'call_0')
                self.assertTrue(refused(answers[-1]), answers)
                self.assertEqual(runs, [goal] if case == 'twice in the same thread' else [])
                self.assertEqual(len(agent.stubs()), 1)

    def test_a_new_permission_is_taken_in_only_once_the_calls_running_have_ended(self):
        agent = Agent(self)
        release = threading.Event()
        first = in_thread(lambda: agent.call('order_supplies', PAPER, lambda a: release.wait(10) and ok(a), 'c1'))[0]
        time.sleep(0.4)
        Permissions.use(self, agent, sign(agent.made, (ORDER, MESSAGE)))
        answer = agent.call('send_message', {'to': 'Sam', 'text': 'hello'}, ok, 'c2')
        self.assertIn('takes the change in once the calls now running have ended', answer)
        release.set()
        first.join(10)
        self.assertFalse(refused(agent.call('send_message', {'to': 'Sam', 'text': 'hello'}, ok, 'c3')))
        check = agent.check()
        self.assertTrue(check['summary']['intact'])
        self.assertEqual([e['kind'] for e in check['entries']], ['slip', 'stub', 'slip', 'stub'])

    def test_a_report_from_outside_a_call_is_used_only_where_one_call_alone_has_its_id(self):
        for together in (1, 2):
            with self.subTest(calls=together):
                agent = Agent(self, actions=(READ,))
                release = threading.Event()
                given = [{'path': f'{n}.txt'} for n in range(together)]
                threads = [in_thread(lambda a=a: agent.call('read_file', a, lambda b: release.wait(10) and ok(b), 'call_0'))[0] for a in given]
                time.sleep(0.5)
                agent.recorder.on_transform_tool_result('read_file', {'path': 'z.txt'}, 'call_0')  # no context: Hermes's own thread
                release.set()
                for t in threads:
                    t.join(10)
                named = sorted(s['details'][0]['sha256'] for s in agent.stubs())
                if together == 1:
                    self.assertEqual(named, [arguments_fingerprint({'path': 'z.txt'})])
                else:
                    self.assertEqual(named, sorted(arguments_fingerprint(a) for a in given))

    def test_a_report_with_a_status_is_taken_only_from_the_call_s_own_context(self):
        for status, args in (('blocked', PAPER), ('ok', dict(PAPER, quantity=500))):
            with self.subTest(status=status):
                agent = Agent(self)
                release = threading.Event()
                thread = in_thread(lambda: agent.call('order_supplies', PAPER, lambda a: release.wait(10) and ok(a), 'call-1'))[0]
                time.sleep(0.4)
                agent.recorder.on_post_tool_call('order_supplies', args, 'call-1', status=status)  # from outside the call
                release.set()
                thread.join(10)
                self.assertEqual([s['details'][0]['sha256'] for s in agent.stubs()], [arguments_fingerprint(PAPER)])

    def test_a_call_hermes_stopped_while_preparing_it_leaves_no_stub(self):
        cancelled = hermes_class('agent.terminal_approval_batch', '_CancelledPreparation')
        agent = Agent(self)

        def tool(args):
            raise cancelled('Terminal approval preparation cancelled; command was not started')

        with self.assertRaises(cancelled):
            agent.call('order_supplies', PAPER, tool)
        self.assertEqual(agent.stubs(), [])

    def test_each_reading_of_a_command_finds_what_the_others_do_not(self):
        rows = [('RM -r build', 'delete'),                                 # the first reading alone
                ('docker exec web shred -u secrets.txt', 'delete'),        # the second reading alone
                ('npx npm --otp=1 publish', 'release'),                    # the second reading alone
                ('git clean -n', 'delete')]                                # the third reading alone
        self.assertEqual({c: command_action(c) for c, _ in rows}, {c: KIND[k] for c, k in rows})


if __name__ == '__main__':
    with warnings.catch_warnings():
        unittest.main()
