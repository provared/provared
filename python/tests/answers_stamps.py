# Shared test cases: how each kind of case is answered by this library.
#
# The tree of fingerprints, DER, outside time-stamps, block time-stamps,
# the chain of block headers and the seal. Each answer is shaped exactly as
# the JavaScript one in test/helpers/vectors-stamps.mjs.

from provared.blockstamp import block_fingerprint, block_stamp_item, check_block_stamp
from provared.der import children, ecdsa_to_raw, read_element, time_of, validate_der
from provared.encoding import from_base64url, problem_from
from provared.headers import answer_for, blocks_in_chain, check_header_chain, next_bits, read_header_chain, start_header_chain
from provared.seal import decode_stamps, key_set_fingerprint, validate_seal_content
from provared.timestamp import check_stamp
from provared.tree import inclusion_path, leaf_hash, tree_builder, tree_root, verify_inclusion


def _answer(work):
    try:
        return {'ok': work()}
    except Exception as e:
        return {'refused': problem_from(e)}


def _bytes(text):
    return bytes.fromhex(text)


def _changed(data, change):
    """A copy of some bytes, changed as a case says: one byte flipped, cut short, or more bytes after."""
    out = bytearray(data)
    if not change:
        return bytes(out)
    if change.get('flip'):
        at, mask = change['flip']
        out[at] ^= mask
    if change.get('cut') is not None:
        out = out[:change['cut']]
    if change.get('append'):
        out += _bytes(change['append'])
    return bytes(out)


def _given(c, name, decode, change=None):
    """A case's bytes, or the value it gives where the bytes are to be something else."""
    if name + 'Value' in c:
        return c[name + 'Value']
    return _changed(decode(c[name]), change)


# --- the tree ---


def _tree_builder(c):
    builder = tree_builder()
    roots = [builder.root().hex()]
    fork = None
    leaves = c['leaves']
    for i, leaf in enumerate(leaves):
        if c.get('forkAt') == i:
            fork = builder.fork()
        builder.add(_bytes(leaf))
        roots.append(builder.root().hex())
    if c.get('forkAt') == len(leaves):
        fork = builder.fork()
    fork_roots = []
    if fork is not None:
        for leaf in c['forkLeaves']:
            fork.add(_bytes(leaf))
            fork_roots.append(fork.root().hex())
    return {'roots': roots, 'forkRoots': fork_roots, 'after': builder.root().hex()}


# --- DER ---


def _children(c):
    data = _bytes(c['bytes'])
    parent = read_element(data, 0)
    most = c.get('most')
    found = children(data, parent) if most is None else children(data, parent, most)
    return [e.as_dict() for e in found]


def _validate_der(c):
    data = _bytes(c['bytes'])
    validate_der(data, read_element(data, 0))
    return True


def _time_of(c):
    data = _bytes(c['bytes'])
    return time_of(data, read_element(data, 0))


# --- the seal ---


def _validate_seal_content(c):
    validate_seal_content(c['content'])
    return True


def _decode_stamps(c):
    out = []
    for s in decode_stamps(c['stamps']):
        if s['kind'] == 'service':
            out.append({'kind': s['kind'], 'token': s['token'].hex()})
        else:
            out.append({'kind': s['kind'], 'header': s['header'].hex(), 'proof': s['proof'].hex()})
    return out


# --- the chain of block headers ---


def _rules(r):
    """The rules of a chain, as a case writes them (whole numbers that may be large as hexadecimal)."""
    if r is None:
        return None
    rules = dict(r)
    rules['limit'] = int(r['limit'], 16)
    if 'ease' in r:
        rules['ease'] = int(r['ease'])
    return rules


def _chain_answer(chain, c):
    height = chain.height
    out = {'height': height}
    if height >= 0:
        out['tip'] = chain.fingerprint_at(height)
        out['tipTime'] = chain.time_at(height)
        out['size'] = len(chain.bytes())
        out['lastHash'] = chain.hash_at(height).hex()
    if c.get('lookups') is not None:
        out['found'] = [chain.height_of(fp) for fp in c['lookups']]
    if c.get('workAfter') is not None:
        out['work'] = format(chain.work_after(c['workAfter']), 'x')
    return out


def _read_header_chain(c):
    o = {'now': c['now']}
    if c.get('partial') is not None:
        o['partial'] = c['partial']
    if c.get('rules'):
        o['rules'] = _rules(c['rules'])
    return _chain_answer(read_header_chain(_changed(_bytes(c['bytes']), c.get('change')), **o), c)


def _check_header_chain(c):
    r = check_header_chain(_given(c, 'bytes', _bytes, c.get('change')), now=c['now'])
    return {'height': r['height'], 'tip': r['tip'], 'tipWhen': r['tipWhen']}


def _header_chain_steps(c):
    chains = [start_header_chain(_rules(c['rules']))]
    out = []
    for step in c['steps']:
        try:
            chain = chains[step.get('chain', 0)]
            op = step['op']
            if op == 'add':
                chain.add(step['value'] if 'value' in step else _bytes(step['header']), step['now'])
                r = {'height': chain.height}
            elif op == 'keepTo':
                chain.keep_to(step['height'])
                r = {'height': chain.height}
            elif op == 'copy':
                chains.append(chain.copy())
                r = {'chains': len(chains)}
            elif op == 'adopt':
                chain.adopt(chains[step['from']])
                r = {'height': chain.height}
            else:
                r = _chain_answer(chain, step)
            out.append({'ok': r})
        except Exception as e:
            out.append({'refused': problem_from(e)})
    return out


def _answer_for(c):
    chain = read_header_chain(_bytes(c['bytes']), now=c['now'], rules=_rules(c['rules']))
    a = answer_for(chain)
    return {'height': a['height'], 'tip': a['tip'], 'tipWhen': a['tipWhen'], 'found': [a['find'](fp) for fp in c['lookups']]}


def _blocks_in_chain(c):
    table = c['chain']
    return blocks_in_chain(c['result'], {'find': lambda fp: table[fp] if fp in table else None})


def _next_bits(c):
    rules = _rules(c.get('rules'))
    return next_bits(c['bits'], c['firstTime'], c['lastTime']) if rules is None else next_bits(c['bits'], c['firstTime'], c['lastTime'], rules)


ANSWER = {
    'nextBits': lambda c: _answer(lambda: _next_bits(c)),
    'readHeaderChain': lambda c: _answer(lambda: _read_header_chain(c)),
    'checkHeaderChain': lambda c: _answer(lambda: _check_header_chain(c)),
    'headerChainSteps': lambda c: _answer(lambda: _header_chain_steps(c)),
    'answerFor': lambda c: _answer(lambda: _answer_for(c)),
    'blocksInChain': lambda c: _answer(lambda: _blocks_in_chain(c)),
    'leafHash': lambda c: _answer(lambda: leaf_hash(_bytes(c['leaf'])).hex()),
    'treeRoot': lambda c: _answer(lambda: tree_root([_bytes(x) for x in c['leaves']]).hex()),
    'treeBuilder': lambda c: _answer(lambda: _tree_builder(c)),
    'inclusionPath': lambda c: _answer(lambda: [p.hex() for p in inclusion_path([_bytes(x) for x in c['leaves']], c['index'])]),
    'verifyInclusion': lambda c: _answer(lambda: verify_inclusion(c['index'], c['size'], _bytes(c['leaf']), [_bytes(p) for p in c['path']], _bytes(c['root']))),
    'readElement': lambda c: _answer(lambda: read_element(_bytes(c['bytes']), c['at'], c.get('end')).as_dict()),
    'children': lambda c: _answer(lambda: _children(c)),
    'validateDer': lambda c: _answer(lambda: _validate_der(c)),
    'timeOf': lambda c: _answer(lambda: _time_of(c)),
    'ecdsaToRaw': lambda c: _answer(lambda: ecdsa_to_raw(_bytes(c['der']), c['size']).hex()),
    'checkStamp': lambda c: _answer(lambda: check_stamp(_given(c, 'token', from_base64url, c.get('change')), _given(c, 'stamped', from_base64url), c.get('options'))),
    'checkBlockStamp': lambda c: _answer(
        lambda: check_block_stamp(
            _given(c, 'proof', _bytes, c.get('change')),
            _given(c, 'header', _bytes, c.get('headerChange')),
            _given(c, 'stamped', _bytes),
            c.get('trusted'),
        )
    ),
    'blockFingerprint': lambda c: _answer(lambda: block_fingerprint(_bytes(c['header']))),
    'blockStampItem': lambda c: _answer(lambda: block_stamp_item(_given(c, 'proof', _bytes), _given(c, 'header', _bytes))),
    'validateSealContent': lambda c: _answer(lambda: _validate_seal_content(c)),
    'decodeStamps': lambda c: _answer(lambda: _decode_stamps(c)),
    'keySetFingerprint': lambda c: _answer(lambda: key_set_fingerprint(c['keys'])),
}
