# "hermes provared init" prints the fingerprint of the agent's key set, which
# the signing window asks for before it signs for keys it has not seen. The
# value must be the one the JavaScript library's keySetFingerprint gives for
# the same keys, as the signing window works it out: tested against the
# shared test file test-vectors/seal-key-sets.json, which the JavaScript
# library writes (tools/make-vectors.mjs), as python/tests/test_vectors.py
# reads it.
#
# Run from this package's folder, with its own environment:
#   .venv/Scripts/python -m unittest discover -s tests

import contextlib
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'src'))

from provared import key_set_fingerprint  # noqa: E402

from provared_hermes import cli  # noqa: E402
from provared_hermes.folder import Folder  # noqa: E402

VECTORS = HERE.parents[3] / 'test-vectors'
PRINTED = re.compile(r"The fingerprint of the agent's key set: ([A-Za-z0-9_-]{43})$", re.M)


def init(folder):
    with contextlib.redirect_stdout(io.StringIO()) as said:
        code = cli.main(['--folder', str(folder), 'init'])
    return code, said.getvalue()


class InitFingerprint(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix='provared-hermes-init-'))
        self.addCleanup(shutil.rmtree, self.folder, ignore_errors=True)

    def test_init_prints_the_fingerprint_of_the_keys_it_made_and_says_the_signing_window_asks_for_it(self):
        code, said = init(self.folder)
        self.assertEqual(code, 0, said)
        found = PRINTED.search(said)
        self.assertIsNotNone(found, said)
        public, _ = Folder(self.folder).agent_keys()
        self.assertEqual(found.group(1), key_set_fingerprint(public))
        self.assertIn('The signing window asks for this fingerprint before you sign', said)
        # Copied only once the window is open, as the recorder's init says it.
        self.assertIn('Copy it from here only once the signing window has opened, and check that what the box then shows is the one printed here.', said)
        # Run again, with the keys there: the same fingerprint.
        self.assertEqual(PRINTED.search(init(self.folder)[1]).group(1), found.group(1))

    def test_the_printed_fingerprint_is_the_javascript_librarys_for_the_same_keys(self):
        cases = json.loads((VECTORS / 'seal-key-sets.json').read_text(encoding='utf-8'))
        self.assertEqual(cases['function'], 'keySetFingerprint')
        case = next(c for c in cases['cases'] if c['name'] == "an agent's key set")
        # The keys init makes, replaced by the test file's, whose fingerprint the JavaScript library gave.
        with mock.patch.object(Folder, 'make_keys', return_value=case['keys']):
            code, said = init(self.folder)
        self.assertEqual(code, 0, said)
        self.assertEqual(PRINTED.search(said).group(1), case['expected']['ok'])


if __name__ == '__main__':
    unittest.main()
