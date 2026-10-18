# The tree of fingerprints: a Merkle tree built exactly as RFC 6962
# (Certificate Transparency), section 2.1, sets out, with SHA-256.
#
#   leaf  = SHA-256(0x00 || data)
#   node  = SHA-256(0x01 || left || right)
#   a tree of n leaves splits at the largest power of two smaller than n
#
# The proof that one leaf is in the tree is the audit path of section
# 2.1.1. It is checked with the steps of RFC 9162, section 2.1.3.2.

import math

from . import _js
from .encoding import sha256

_LEAF = b'\x00'
_NODE = b'\x01'


def leaf_hash(data):
    return sha256(_LEAF + bytes(data))


def _node_hash(left, right):
    return sha256(_NODE + bytes(left) + bytes(right))


def _levels(leaf_hashes):
    """Every level of the tree, from the leaf hashes up to the root. Pairing
    neighbours and carrying a last odd node up unchanged gives the same tree
    as the recursive definition in RFC 6962: the test vectors prove it."""
    everything = [leaf_hashes]
    level = leaf_hashes
    while len(level) > 1:
        following = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            following.append(level[-1])
        everything.append(following)
        level = following
    return everything


def tree_root(leaves):
    """The root of the tree over the given leaves: the top fingerprint.

    leaves: the data of each leaf. Returns 32 bytes; for no leaves, the hash
    of nothing, as RFC 6962 defines.
    """
    leaves = list(leaves)
    if len(leaves) == 0:
        return sha256(b'')
    everything = _levels([leaf_hash(leaf) for leaf in leaves])
    return everything[-1][0]


class TreeBuilder:
    """Work out the root as the leaves arrive, one at a time, so that the root
    of the first n leaves is at hand after each. It keeps one fingerprint
    for each complete part of the tree and folds them together from the
    right. This is the same tree as tree_root gives: the tests compare the
    two at every size."""

    __slots__ = ('_parts',)

    def __init__(self, parts=()):
        # Each part: (hash, size).
        self._parts = list(parts)

    def fork(self):
        """A builder that carries on from here by itself: what is added to one is not added to the other."""
        return TreeBuilder(self._parts)

    def add(self, leaf):
        """leaf: the data of the next leaf."""
        node_hash, size = leaf_hash(leaf), 1
        while self._parts and self._parts[-1][1] == size:
            left_hash, left_size = self._parts.pop()
            node_hash, size = _node_hash(left_hash, node_hash), left_size * 2
        self._parts.append((node_hash, size))

    def root(self):
        """The root of the leaves added so far."""
        if len(self._parts) == 0:
            return sha256(b'')
        result = self._parts[-1][0]
        for i in range(len(self._parts) - 2, -1, -1):
            result = _node_hash(self._parts[i][0], result)
        return result


def tree_builder(start=()):
    return TreeBuilder(start)


def _is_integer(value):
    """Number.isInteger"""
    return _js.is_number(value) and math.isfinite(value) and value == int(value)


def inclusion_path(leaves, index):
    """The audit path for one leaf: the fingerprints needed to work out the root
    from that leaf alone.

    leaves: the data of each leaf. index: which leaf, counting from 0.
    Raises IndexError ("no such leaf"), where JavaScript throws a RangeError.
    """
    leaves = list(leaves)
    if not _is_integer(index) or index < 0 or index >= len(leaves):
        raise IndexError('no such leaf')
    everything = _levels([leaf_hash(leaf) for leaf in leaves])
    path = []
    at = int(index)
    for depth in range(len(everything) - 1):
        level = everything[depth]
        if at % 2 == 1:
            path.append(level[at - 1])
        elif at + 1 < len(level):
            path.append(level[at + 1])
        # else: a last odd node, carried up with no neighbour at this level.
        at //= 2
    return path


def verify_inclusion(index, size, leaf, path, root):
    """Check an audit path (RFC 9162, section 2.1.3.2).

    index: which leaf, counting from 0. size: how many leaves the tree has.
    leaf: the data of the leaf. Returns True or False.
    """
    if not _js.is_safe_integer(index) or not _js.is_safe_integer(size) or index < 0 or index >= size:
        return False
    fn = int(index)
    sn = int(size) - 1
    r = leaf_hash(leaf)
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = _node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            r = _node_hash(r, p)
        fn //= 2
        sn //= 2
    return sn == 0 and r == bytes(root)


# --- consistency proofs: RFC 9162, section 2.1.4 ---


def _split_at(n):
    """The largest power of two smaller than n, for n of 2 or more (RFC 9162, section 2.1.1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _range_root(hashes, lo, hi):
    """The root of the tree over hashes[lo:hi], for hi > lo: MTH of RFC 9162, section 2.1.1."""
    if hi - lo == 1:
        return hashes[lo]
    k = _split_at(hi - lo)
    return _node_hash(_range_root(hashes, lo, lo + k), _range_root(hashes, lo + k, hi))


def _subproof(hashes, m, lo, hi, b):
    """SUBPROOF(m, D[lo:hi], b) of RFC 9162, section 2.1.4.1, for 0 < m <= hi - lo."""
    n = hi - lo
    if m == n:
        return [] if b else [_range_root(hashes, lo, hi)]
    k = _split_at(n)
    if m <= k:
        return [*_subproof(hashes, m, lo, lo + k, b), _range_root(hashes, lo + k, hi)]
    return [*_subproof(hashes, m - k, lo + k, hi, False), _range_root(hashes, lo, lo + k)]


def consistency_proof(leaves, m):
    """The proof that the first m leaves form a tree that the whole tree
    extends: the consistency proof of RFC 9162, section 2.1.4.1. For m equal
    to the number of leaves, and for m of 0, the proof is empty.

    leaves: the data of each leaf. Raises TypeError where the leaves are not
    a list, and IndexError ("no such earlier tree") where JavaScript throws a
    RangeError.
    """
    if not isinstance(leaves, (list, tuple)):
        raise TypeError('the leaves must be a list')
    leaves = list(leaves)
    if not _js.is_safe_integer(m) or m < 0 or m > len(leaves):
        raise IndexError('no such earlier tree')
    m = int(m)
    if m == 0 or m == len(leaves):
        return []
    hashes = [leaf_hash(leaf) for leaf in leaves]
    return _subproof(hashes, m, 0, len(hashes), True)


def _is_hash(value):
    return isinstance(value, (bytes, bytearray)) and len(value) == 32


def verify_consistency(m, n, root_m, root_n, proof):
    """Check a consistency proof (RFC 9162, section 2.1.4.2): that the tree of
    m leaves whose root is root_m is the first part of the tree of n leaves
    whose root is root_n. Where m equals n the proof must be empty and the
    two roots the same; where m is 0 the proof must be empty and root_m the
    root of the empty tree. Returns True or False, and never raises for a bad
    proof.
    """
    if not _js.is_safe_integer(m) or not _js.is_safe_integer(n) or m < 0 or m > n:
        return False
    if not _is_hash(root_m) or not _is_hash(root_n) or not isinstance(proof, (list, tuple)):
        return False
    path = []
    for p in proof:
        if not _is_hash(p):
            return False
        path.append(bytes(p))
    m = int(m)
    n = int(n)
    root_m = bytes(root_m)
    root_n = bytes(root_n)
    if m == n:
        return len(path) == 0 and root_m == root_n
    if m == 0:
        return len(path) == 0 and root_m == sha256(b'')
    # The steps of RFC 9162, section 2.1.4.2, in their order.
    # 1. An empty proof fails.
    if len(path) == 0:
        return False
    # 2. Where m is an exact power of two, the root of the earlier tree is the first value.
    power = 1
    while power < m:
        power *= 2
    if power == m:
        path.insert(0, root_m)
    # 3.
    fn = m - 1
    sn = n - 1
    # 4.
    while fn % 2 == 1:
        fn //= 2
        sn //= 2
    # 5.
    fr = path[0]
    sr = path[0]
    # 6.
    for c in path[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = _node_hash(c, fr)
            sr = _node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            sr = _node_hash(sr, c)
        fn //= 2
        sn //= 2
    # 7.
    return fr == root_m and sr == root_n and sn == 0
