# Public keys: the exact shapes the format accepts (format description,
# section 3.8), their thumbprints (RFC 7638) and how each is loaded for
# checking a signature.

from . import _js
from .encoding import Refusal, from_base64url, sha256, to_base64url, utf8

KEY_SET_METHODS = ['Ed25519', 'ML-DSA-87']
"""The signing methods of an agent's or a service's key set, in order."""

SEAL_METHODS = ['Ed25519', 'ML-DSA-87', 'SLH-DSA-SHA2-256s']
"""The signing methods of a recorder's key set, which signs seals, in order.
The third rests only on fingerprint functions (FIPS 205)."""

PASSKEY_METHODS = ['ES256', 'RS256', 'Ed25519']
"""The signing methods a passkey may use."""

# For each method: the exact members of its JSON Web Key, in sorted order.
_SHAPES = {
    'Ed25519': ['alg', 'crv', 'kty', 'x'],
    'ML-DSA-87': ['alg', 'kty', 'pub'],
    'SLH-DSA-SHA2-256s': ['alg', 'kty', 'pub'],
    'ES256': ['alg', 'crv', 'kty', 'x', 'y'],
    'RS256': ['alg', 'e', 'kty', 'n'],
}


def _bad(where, why):
    return Refusal('bad-key', f'{where}: {why}')


def _bytes_of(jwk, member, where):
    try:
        return from_base64url(jwk[member])
    except Refusal:
        raise _bad(where, f'"{member}" is not base64url.') from None


def check_key(jwk, allowed, where):
    """Confirm that a key is exactly one of the accepted shapes. Returns its method."""
    if not isinstance(jwk, dict):
        raise _bad(where, 'a key must be an object.')
    alg = jwk.get('alg')
    if not isinstance(alg, str) or alg not in allowed or alg not in _SHAPES:
        raise _bad(where, f'the signing method must be one of {", ".join(allowed)}.')
    names = _js.sort_strings(jwk.keys())
    expected = _SHAPES[alg]
    if names != expected:
        raise _bad(where, f'a {alg} key must hold exactly {", ".join(expected)}.')
    for n in names:
        if not isinstance(jwk[n], str):
            raise _bad(where, f'"{n}" must be text.')
    if alg == 'Ed25519':
        if jwk['kty'] != 'OKP' or jwk['crv'] != 'Ed25519':
            raise _bad(where, 'an Ed25519 key has kty OKP and crv Ed25519.')
        if len(_bytes_of(jwk, 'x', where)) != 32:
            raise _bad(where, 'an Ed25519 public key is 32 bytes.')
    elif alg == 'ML-DSA-87':
        if jwk['kty'] != 'AKP':
            raise _bad(where, 'an ML-DSA-87 key has kty AKP.')
        # FIPS 204, table 2: an ML-DSA-87 public key is 2,592 bytes.
        if len(_bytes_of(jwk, 'pub', where)) != 2592:
            raise _bad(where, 'an ML-DSA-87 public key is 2,592 bytes.')
    elif alg == 'SLH-DSA-SHA2-256s':
        if jwk['kty'] != 'AKP':
            raise _bad(where, 'an SLH-DSA key has kty AKP.')
        # FIPS 205, table 2: an SLH-DSA-SHA2-256s public key is 64 bytes.
        if len(_bytes_of(jwk, 'pub', where)) != 64:
            raise _bad(where, 'an SLH-DSA-SHA2-256s public key is 64 bytes.')
    elif alg == 'ES256':
        if jwk['kty'] != 'EC' or jwk['crv'] != 'P-256':
            raise _bad(where, 'an ES256 key has kty EC and crv P-256.')
        if len(_bytes_of(jwk, 'x', where)) != 32 or len(_bytes_of(jwk, 'y', where)) != 32:
            raise _bad(where, 'the two halves of a P-256 public key are 32 bytes each.')
    else:
        if jwk['kty'] != 'RSA' or jwk['e'] != 'AQAB':
            raise _bad(where, 'an RS256 key has kty RSA and e AQAB.')
        n = _bytes_of(jwk, 'n', where)
        # The size in bits: whole bytes after the first, and the bits of the first.
        bits = 0 if len(n) == 0 or n[0] == 0 else (len(n) - 1) * 8 + n[0].bit_length()
        if bits < 2048 or bits > 8192:
            raise _bad(where, 'an RS256 key is 2,048 to 8,192 bits.')
    return alg


def check_key_set(keys, where):
    """Confirm that a value is a key set: exactly an Ed25519 key, then an
    ML-DSA-87 key (format description, section 3.9)."""
    if not isinstance(keys, list) or len(keys) != len(KEY_SET_METHODS):
        raise _bad(where, 'a key set is exactly two keys: Ed25519, then ML-DSA-87.')
    for i, alg in enumerate(KEY_SET_METHODS):
        check_key(keys[i], [alg], f'{where}[{i}]')


def check_seal_key_set(keys, where):
    """Confirm that a value is a recorder's key set: exactly an Ed25519 key, an
    ML-DSA-87 key and an SLH-DSA-SHA2-256s key, in that order."""
    if not isinstance(keys, list) or len(keys) != len(SEAL_METHODS):
        raise _bad(where, "a recorder's key set is exactly three keys: Ed25519, ML-DSA-87, then SLH-DSA-SHA2-256s.")
    for i, alg in enumerate(SEAL_METHODS):
        check_key(keys[i], [alg], f'{where}[{i}]')


def thumbprint(jwk):
    """The thumbprint of a key: RFC 7638 with SHA-256. The members used are those
    RFC 7638 section 3.2 names, and for ML-DSA those RFC 9964 section 6 names.
    The key must already have passed check_key."""
    required = dict(jwk)
    # "alg" is part of the thumbprint only for the AKP key type.
    if jwk.get('kty') != 'AKP':
        required.pop('alg', None)
    names = _js.sort_strings(required.keys())
    text = '{' + ','.join(_js.string(n) + ':' + _js.string(required[n]) for n in names) + '}'
    return to_base64url(sha256(utf8(text)))
