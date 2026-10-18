# Consistency proofs (RFC 9162, section 2.1.4) against the recursive
# definition of section 2.1.4.1, written out here on its own, for every pair
# of tree sizes up to 64 and some larger random trees; and the witness
# statement written and read in this library. The checker's answers for
# books with witness statements are in the shared test files
# (witness-*.json): this library writes no seals, having no SLH-DSA.

import hashlib
import random
import unittest

from provared import write_witness
from provared.encoding import Refusal, from_base64url
from provared.jws import parse_record, signing_input
from provared.signatures import generate_key_set, verify_signature
from provared.tree import consistency_proof, leaf_hash, tree_root, verify_consistency
from provared.witness import validate_witness_content


def _h(*parts):
    return hashlib.sha256(b''.join(parts)).digest()


def _mth(data):
    """MTH of RFC 9162, section 2.1.1, over the leaves' data."""
    if len(data) == 0:
        return _h()
    if len(data) == 1:
        return _h(b'\x00', data[0])
    k = 1
    while k * 2 < len(data):
        k *= 2
    return _h(b'\x01', _mth(data[:k]), _mth(data[k:]))


def _subproof(m, data, b):
    """SUBPROOF(m, D[n], b) of RFC 9162, section 2.1.4.1."""
    n = len(data)
    if m == n:
        return [] if b else [_mth(data)]
    k = 1
    while k * 2 < n:
        k *= 2
    if m <= k:
        return _subproof(m, data[:k], b) + [_mth(data[k:])]
    return _subproof(m - k, data[k:], False) + [_mth(data[:k])]


class ConsistencyProofs(unittest.TestCase):
    def test_every_pair_up_to_64(self):
        data = [f'leaf {i}'.encode() for i in range(64)]
        roots = [_mth(data[:n]) for n in range(65)]
        for n in range(1, 65):
            self.assertEqual(tree_root(data[:n]), roots[n])
            for m in range(1, n + 1):
                proof = consistency_proof(data[:n], m)
                self.assertEqual(proof, _subproof(m, data[:n], True), f'{m} to {n}')
                self.assertTrue(verify_consistency(m, n, roots[m], roots[n], proof), f'{m} to {n}')
                if m < n:
                    self.assertFalse(verify_consistency(m, n, roots[m], roots[n - 1], proof))
                    self.assertFalse(verify_consistency(m, n, roots[m - 1], roots[n], proof))
                    for i in range(len(proof)):
                        changed = list(proof)
                        changed[i] = bytes([changed[i][0] ^ 1]) + changed[i][1:]
                        self.assertFalse(verify_consistency(m, n, roots[m], roots[n], changed), f'{m} to {n}, value {i}')
                        self.assertFalse(verify_consistency(m, n, roots[m], roots[n], proof[:i] + proof[i + 1:]), f'{m} to {n}, value {i} left out')

    def test_random_large_trees(self):
        rand = random.Random(9162)
        for size in [1000, 1023, 1024, 1025, rand.randint(2000, 5000)]:
            data = [rand.randbytes(rand.randint(0, 40)) for _ in range(size)]
            root = tree_root(data)
            for m in sorted({1, 2, size // 3, size // 2, size - 1, size, rand.randint(1, size)}):
                proof = consistency_proof(data, m)
                self.assertEqual(proof, _subproof(m, data, True))
                self.assertTrue(verify_consistency(m, size, tree_root(data[:m]), root, proof))

    def test_the_edges(self):
        data = [bytes([i]) for i in range(8)]
        self.assertEqual(consistency_proof(data, 0), [])
        self.assertEqual(consistency_proof(data, 8), [])
        self.assertTrue(verify_consistency(0, 8, _h(), tree_root(data), []))
        self.assertFalse(verify_consistency(0, 8, leaf_hash(data[0]), tree_root(data), []))
        self.assertTrue(verify_consistency(8, 8, tree_root(data), tree_root(data), []))
        self.assertFalse(verify_consistency(8, 8, tree_root(data), tree_root(data[:7]), []))
        self.assertFalse(verify_consistency(3, 8, tree_root(data[:3]), tree_root(data), []))
        self.assertFalse(verify_consistency(3, 8, tree_root(data[:3]), tree_root(data), 'x'))
        self.assertFalse(verify_consistency(3.5, 8, tree_root(data[:3]), tree_root(data), []))
        self.assertFalse(verify_consistency(True, 8, tree_root(data[:3]), tree_root(data), []))
        for bad in [9, -1, 1.5, '1', None, True]:
            with self.assertRaises((IndexError, TypeError)):
                consistency_proof(data, bad)


class WitnessStatements(unittest.TestCase):
    def test_a_statement_written_here_reads_and_checks(self):
        keys, private_keys = generate_key_set()
        by = {'keys': keys, 'name': 'Example witness (invented)'}
        seal = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE'
        root = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM'
        out = write_witness({'seal': seal, 'size': 12, 'root': root, 'by': by, 'when': 0}, private_keys)
        parsed = parse_record(out['record'], 'witness')
        self.assertEqual(parsed.fingerprint, out['fingerprint'])
        validate_witness_content(parsed.content)
        self.assertEqual(parsed.content['seal'], seal)
        for i, s in enumerate(parsed.signatures):
            self.assertEqual(verify_signature(by['keys'][i], s['signature'], signing_input(s['protected_b64'], parsed.payload_b64)), 'valid')
        with self.assertRaises(Refusal):
            write_witness({'seal': seal, 'size': 0, 'root': root, 'by': by}, private_keys)
        # A statement is not a seal, nor a seal a statement.
        with self.assertRaises(Refusal):
            parse_record(out['record'], 'seal')
        self.assertTrue(from_base64url(out['fingerprint']))


if __name__ == '__main__':
    unittest.main()
