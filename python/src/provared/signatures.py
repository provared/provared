# Checking and making signatures, with the package "cryptography", which
# rests on OpenSSL as Node.js does.
#
# Methods:
#   Ed25519    RFC 8032
#   ML-DSA-87  FIPS 204, plain method, empty context (RFC 9964 section 5)
#   ES256      ECDSA with P-256 and SHA-256 (FIPS 186-5), passkeys only
#   RS256      RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017), passkeys only
#   SLH-DSA-SHA2-256s  FIPS 205, plain method, empty context; seals only
#
# SLH-DSA is not yet in "cryptography". It is reported as not built in,
# which is never a pass, as on a device whose browser lacks a method.

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .encoding import from_base64url, to_base64url
from .keys import weak_ed25519

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa

    _ML = _mldsa.MLDSA87PublicKey
except ImportError:  # "cryptography" before version 48
    _mldsa = None
    _ML = None

SLH = 'SLH-DSA-SHA2-256s'


def method_available(alg):
    """Whether this device can check signatures made with this method."""
    if alg in ('ES256', 'RS256', 'Ed25519'):
        return True
    if alg == 'ML-DSA-87':
        return _ML is not None
    return False


def _load(jwk):
    alg = jwk['alg']
    if alg == 'Ed25519':
        return ed25519.Ed25519PublicKey.from_public_bytes(from_base64url(jwk['x']))
    if alg == 'ML-DSA-87':
        return _ML.from_public_bytes(from_base64url(jwk['pub']))
    if alg == 'ES256':
        x = int.from_bytes(from_base64url(jwk['x']), 'big')
        y = int.from_bytes(from_base64url(jwk['y']), 'big')
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if alg == 'RS256':
        n = int.from_bytes(from_base64url(jwk['n']), 'big')
        e = int.from_bytes(from_base64url(jwk['e']), 'big')
        return rsa.RSAPublicNumbers(e, n).public_key()
    raise ValueError('unknown signing method')


def verify_signature(jwk, signature, data, without=()):
    """Check one signature: 'valid', 'invalid' or 'unavailable'.

    "unavailable" means this device has no built-in support for the method. It
    is never treated as a pass. On a device that has the method, any failure,
    including a key the device refuses to load, is "invalid". "without" names
    methods to treat as not built in, to see how a check behaves on a device
    without them; it can only withhold a pass.
    """
    alg = jwk['alg']
    if alg == SLH:
        return 'unavailable'
    if alg not in ('Ed25519', 'ML-DSA-87', 'ES256', 'RS256'):
        return 'invalid'
    if alg in without or not method_available(alg):
        return 'unavailable'
    signature = bytes(signature)
    data = bytes(data)
    # An Ed25519 signature whose first half is a point of small order is
    # refused here, whatever the library beneath would say: libraries
    # differ on it (format description, section 3.8).
    if alg == 'Ed25519' and (len(signature) != 64 or weak_ed25519(signature[:32])):
        return 'invalid'
    try:
        key = _load(jwk)
        if alg == 'ES256':
            # Web Crypto checks the two numbers side by side, 32 bytes each.
            if len(signature) != 64:
                return 'invalid'
            der = encode_dss_signature(int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big'))
            key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        elif alg == 'RS256':
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(signature, data)
        return 'valid'
    except InvalidSignature:
        return 'invalid'
    except Exception:
        return 'invalid'


def sign(alg, private_key, data):
    """Sign with one private key of a key set: 'Ed25519' or 'ML-DSA-87'."""
    if alg == SLH:
        raise ValueError('SLH-DSA is not built into this device.')
    return private_key.sign(bytes(data))


def generate_key_set():
    """Make a new key set for an agent or a service: an Ed25519 key and an
    ML-DSA-87 key. Returns the public key set and the private keys, in the
    same order. The private keys stay in the memory of this process."""
    if _mldsa is None:
        raise RuntimeError('ML-DSA is not built into this device: "cryptography" 48 or later is needed.')
    return _key_set(ed25519.Ed25519PrivateKey.generate(), _mldsa.MLDSA87PrivateKey.generate())


def _key_set(ed, ml):
    ed_x = ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ml_pub = ml.public_key().public_bytes_raw()
    keys = [
        {'alg': 'Ed25519', 'crv': 'Ed25519', 'kty': 'OKP', 'x': to_base64url(ed_x)},
        {'alg': 'ML-DSA-87', 'kty': 'AKP', 'pub': to_base64url(ml_pub)},
    ]
    return keys, [ed, ml]


def key_set_from_seeds(ed25519_seed, ml_dsa_seed):
    """Load an agent's or a service's key set from its two 32-byte seeds: the
    Ed25519 private key (RFC 8032) and the ML-DSA-87 seed (FIPS 204), as
    key_set_seeds gives them. Returns the public key set and the private
    keys, in the same order, as generate_key_set does. So an agent can keep
    its keys between runs. The seeds are secrets: whoever holds them can
    sign as the agent."""
    if _mldsa is None:
        raise RuntimeError('ML-DSA is not built into this device: "cryptography" 48 or later is needed.')
    ed25519_seed = bytes(ed25519_seed)
    ml_dsa_seed = bytes(ml_dsa_seed)
    if len(ed25519_seed) != 32 or len(ml_dsa_seed) != 32:
        raise ValueError('Each seed must be 32 bytes.')
    return _key_set(ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_seed), _mldsa.MLDSA87PrivateKey.from_seed_bytes(ml_dsa_seed))


def key_set_seeds(private_keys):
    """The two 32-byte seeds of a key set's private keys (Ed25519, then
    ML-DSA-87), as generate_key_set or key_set_from_seeds gives them, for
    key_set_from_seeds. They are secrets: keep them as carefully as the
    keys themselves."""
    ed, ml = private_keys
    return ed.private_bytes_raw(), ml.private_bytes_raw()
