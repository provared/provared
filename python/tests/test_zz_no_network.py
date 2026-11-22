"""The last check of the watch on the network (test_00_no_network.py, the
file that sorts first, puts it in place and states what it watches and its
limits): it fails where library code opened the network while the tests
ran, even where the library caught the error."""

import os
import unittest

from test_00_no_network import TESTS, found


class NoNetworkAtTheEnd(unittest.TestCase):
    def test_1_this_file_sorts_last(self):
        names = sorted(n for n in os.listdir(TESTS) if n.startswith('test') and n.endswith('.py'))
        self.assertEqual(names[-1], os.path.basename(__file__), 'the check below must run after every other test')

    def test_9_no_library_code_opened_the_network(self):
        self.assertEqual(found, [], 'library code opened the network while the tests ran')


if __name__ == '__main__':
    unittest.main()
