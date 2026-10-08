# The tree of fingerprints on large random trees: the root worked out leaf
# by leaf, and every audit path checked, against the recursive definition
# of RFC 6962, section 2.1, written out here on its own.

import hashlib
import random
import unittest

from provared.tree import TreeBuilder, inclusion_path, leaf_hash, tree_root, verify_inclusion


def _rfc_root(hashes):
    """MTH of RFC 6962 section 2.1, over leaf hashes already worked out."""
    if len(hashes) == 1:
        return hashes[0]
    k = 1
    while k * 2 < len(hashes):
        k *= 2
    return hashlib.sha256(b'\x01' + _rfc_root(hashes[:k]) + _rfc_root(hashes[k:])).digest()


def _rfc_path(m, hashes):
    """PATH(m, D[n]) of RFC 6962 section 2.1.1."""
    if len(hashes) == 1:
        return []
    k = 1
    while k * 2 < len(hashes):
        k *= 2
    if m < k:
        return _rfc_path(m, hashes[:k]) + [_rfc_root(hashes[k:])]
    return _rfc_path(m - k, hashes[k:]) + [_rfc_root(hashes[:k])]


class LargeTrees(unittest.TestCase):
    def test_random_trees(self):
        rand = random.Random(6962)
        for size in [1, 2, 3, 63, 64, 65, 1000, 1023, 1025, rand.randint(2000, 5000)]:
            leaves = [rand.randbytes(rand.randint(0, 40)) for _ in range(size)]
            hashes = [leaf_hash(leaf) for leaf in leaves]
            root = tree_root(leaves)
            self.assertEqual(root, _rfc_root(hashes), size)
            for i in sorted({0, size - 1, size // 2, *(rand.randrange(size) for _ in range(20))}):
                path = inclusion_path(leaves, i)
                self.assertEqual(path, _rfc_path(i, hashes), (size, i))
                self.assertTrue(verify_inclusion(i, size, leaves[i], path, root), (size, i))
                self.assertFalse(verify_inclusion(i, size, leaves[i] + b'x', path, root), (size, i))
                self.assertFalse(verify_inclusion(i, size, leaves[i], path, bytes(32)), (size, i))
                if path:
                    changed = list(path)
                    changed[rand.randrange(len(changed))] = bytes(32)
                    self.assertFalse(verify_inclusion(i, size, leaves[i], changed, root), (size, i))

    def test_the_builder_at_every_size(self):
        rand = random.Random(1)
        leaves = [rand.randbytes(rand.randint(0, 8)) for _ in range(3000)]
        hashes = [leaf_hash(leaf) for leaf in leaves]
        builder = TreeBuilder()
        self.assertEqual(builder.root(), hashlib.sha256(b'').digest())
        checks = set(range(1, 70)) | {rand.randint(70, 3000) for _ in range(40)} | {1024, 2048, 3000}
        for n, leaf in enumerate(leaves, 1):
            builder.add(leaf)
            if n in checks:
                self.assertEqual(builder.root(), _rfc_root(hashes[:n]), n)
        # A builder split off goes its own way.
        fork = builder.fork()
        fork.add(b'one more')
        self.assertEqual(builder.root(), _rfc_root(hashes))
        self.assertEqual(fork.root(), _rfc_root(hashes + [leaf_hash(b'one more')]))


if __name__ == '__main__':
    unittest.main()
