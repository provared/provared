# A watch on the network while the library's tests run: library code that
# opens a network connection, sends over UDP or looks up a name makes a test
# fail. The library makes no network request, and unlike the JavaScript
# library it has no network code of its own (no counterpart of net/), so
# nothing in it is left out. Left out by design are the tests' own files in
# this folder, whose helpers may start servers on this computer and talk to
# them.
#
# The watch is an audit hook (sys.addaudithook, Python's own means), put in
# place when "python -m unittest discover -s tests" loads this file. The
# discovery loads every test file before any test runs, so the hook is in
# place for all of them. A call is judged by the innermost frame on its
# stack that is a file of the library or of this folder: in the library, it
# is the library's. Such a call is stopped with NetworkUsed, which derives
# from BaseException so that an "except Exception" in the library does not
# hide it, and is noted; the last test here, in the file that sorts last,
# fails where any call was noted, even one the library caught.
#
# Watched (Python's audit events): socket.connect (connect and connect_ex),
# socket.sendto, socket.sendmsg, socket.getaddrinfo, socket.gethostbyname,
# socket.gethostbyaddr, socket.getnameinfo, http.client.connect and
# urllib.Request.

import os
import socket
import sys
import unittest

import provared


def _folder(path):
    return os.path.normcase(os.path.dirname(os.path.abspath(path))) + os.sep


LIBRARY = _folder(provared.__file__)
TESTS = _folder(__file__)
EVENTS = frozenset({
    'socket.connect', 'socket.sendto', 'socket.sendmsg', 'socket.getaddrinfo',
    'socket.gethostbyname', 'socket.gethostbyaddr', 'socket.getnameinfo',
    'http.client.connect', 'urllib.Request',
})


class NetworkUsed(BaseException):
    """Library code opened the network."""


found = []


def library_file_of(frame):
    """The library file that made the call, or None where the innermost
    frame of the library or of the tests' folder is the tests'."""
    while frame is not None:
        name = os.path.normcase(os.path.abspath(frame.f_code.co_filename))
        if name.startswith(LIBRARY):
            return name
        if name.startswith(TESTS):
            return None
        frame = frame.f_back
    return None


def _hook(event, args):
    if event not in EVENTS:
        return
    where = library_file_of(sys._getframe(1))
    if where is None:
        return
    found.append((event, os.path.relpath(where, LIBRARY).replace(os.sep, '/')))
    raise NetworkUsed(f'Library code opened the network ({event}, from {found[-1][1]}). The library makes no network request.')


if not getattr(sys, '_provared_no_network', False):
    sys._provared_no_network = True
    sys.addaudithook(_hook)


def _run_as_library(code):
    """Runs code as if it were written in a file of the library, so that
    its frames name that file, without changing the file."""
    space = {'socket': socket}
    exec(compile(code, os.path.join(LIBRARY, 'probe_for_a_test.py'), 'exec'), space)  # noqa: S102 -- fixed code written here, run only to give its frames a library file's name


class NoNetwork(unittest.TestCase):
    def _stopped(self, code):
        before = len(found)
        with self.assertRaises(NetworkUsed):
            _run_as_library(code)
        noted = found[before:]
        del found[before:]
        return noted

    def test_1_the_watch_is_in_place(self):
        self.assertTrue(sys._provared_no_network)
        self.assertTrue(LIBRARY.endswith(os.sep + 'provared' + os.sep), LIBRARY)

    def test_2_library_calls_are_stopped(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            calls = {
                'socket.connect': f'with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n    s.settimeout(5)\n    s.connect(("127.0.0.1", {port}))',
                'socket.getaddrinfo': 'socket.getaddrinfo("localhost", 9)',
                'socket.sendto': 's = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ntry:\n    s.sendto(b"x", ("127.0.0.1", 9))\nfinally:\n    s.close()',
                'http.client.connect': f'import http.client\nhttp.client.HTTPConnection("127.0.0.1", {port}, timeout=5).connect()',
            }
            for event, code in calls.items():
                with self.subTest(event):
                    self.assertEqual(self._stopped(code), [(event, 'probe_for_a_test.py')])
        finally:
            listener.close()

    def test_3_a_caught_error_is_still_noted(self):
        before = len(found)
        _run_as_library('try:\n    socket.getaddrinfo("localhost", 9)\nexcept BaseException:\n    pass')
        self.assertEqual(found[before:], [('socket.getaddrinfo', 'probe_for_a_test.py')])
        del found[before:]

    def test_4_the_tests_own_calls_go_through(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        try:
            before = len(found)
            with socket.create_connection(listener.getsockname(), timeout=5):
                pass
            self.assertEqual(found[before:], [])
        finally:
            listener.close()

    def test_5_this_file_sorts_last(self):
        names = sorted(n for n in os.listdir(TESTS) if n.startswith('test') and n.endswith('.py'))
        self.assertEqual(names[-1], os.path.basename(__file__), 'the check below must run after every other test')

    def test_9_no_library_code_opened_the_network(self):
        self.assertEqual(found, [], 'library code opened the network while the tests ran')


if __name__ == '__main__':
    unittest.main()
