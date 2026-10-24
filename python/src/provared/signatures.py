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

import concurrent.futures
import inspect
import threading
from typing import Protocol, runtime_checkable

from .encoding import Refusal, from_base64url, to_base64url
from .keys import bad_ed25519_signature, check_key, thumbprint

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa

    _ML = _mldsa.MLDSA87PublicKey
except ImportError:  # "cryptography" before version 48
    _mldsa = None
    _ML = None

SLH = 'SLH-DSA-SHA2-256s'

# The length of a signature, in bytes, by method (RFC 8032, FIPS 204,
# FIPS 205).
_SIGNATURE_BYTES = {'Ed25519': 64, 'ML-DSA-87': 4627, SLH: 29792}


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
    # A signature of another length than its method's can never check, so it
    # is refused on every device, whether or not this one has the method.
    if alg in _SIGNATURE_BYTES and len(signature) != _SIGNATURE_BYTES[alg]:
        return 'invalid'
    if alg == SLH:
        return 'unavailable'
    if alg not in ('Ed25519', 'ML-DSA-87', 'ES256', 'RS256'):
        return 'invalid'
    if alg in without or not method_available(alg):
        return 'unavailable'
    signature = bytes(signature)
    data = bytes(data)
    # An Ed25519 signature whose first half is a point of small order, or
    # whose second half, the number S, is not below the order L, is refused
    # here, whatever the library beneath would say: libraries differ on
    # both (format description, section 3.8).
    if alg == 'Ed25519' and bad_ed25519_signature(signature):
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


# --- signers ---
#
# Wherever a writer takes "private_keys", each item may be a private key of
# the package "cryptography", used as it always was, or a signer: an
# object with "key", the public key as a JSON Web Key (a dict) in one of
# the shapes of the format description, section 3.8, and "sign(data)",
# which gives the signature over exactly those bytes. A signer lets a key
# live elsewhere: in a key service, or a hardware module. It changes where
# a signature is made, not how: the record is the same.
#
# A signer is not taken on trust. Its two members are read once. Its key
# must be plain data, a key of the method of its place in the list, of a
# method this device can check, and, where the writer knows the key the
# record must be signed with, that key. All of this is settled before any
# signer is asked to sign. Every signature it gives is checked against its
# key before it is used. A signer that fails in any way leaves no record,
# and the error names the method and the key. Signers earlier in the list
# may have signed by then: a key service's own log may hold signatures that
# match no record.


@runtime_checkable
class Signer(Protocol):
    """A key held elsewhere that signs on request: "key", the public key as a
    dict, and "sign(data)", which gives the signature bytes over exactly
    those bytes (64 for Ed25519, 4,627 for ML-DSA-87)."""

    key: dict

    def sign(self, data: bytes) -> bytes: ...


def _platform_key(item, alg):
    """Whether an item of "private_keys" is a private key of the package
    "cryptography" for the method of its place. A key of another method is
    not one."""
    if alg == 'Ed25519':
        return isinstance(item, ed25519.Ed25519PrivateKey)
    if alg == 'ML-DSA-87':
        return _mldsa is not None and isinstance(item, _mldsa.MLDSA87PrivateKey)
    return False


def _signer_shape(alg):
    """What a place in "private_keys" must hold."""
    return (f'must be a private key for {alg} (of the package "cryptography"), or a signer: an object with "key", '
            'the public key, and "sign", a function that gives the signature bytes.')


_PLAIN = (str, int, float, bool, type(None), list, dict)


def _plain_key(key, where):
    """A copy of a key handed over, refused unless it is plain data: a dict
    whose names are text and whose values are of the plain kinds, not of a
    kind derived from them. A text derived from str could say that it equals
    another key's text. Anything that is not a dict at all is left to
    check_key, which says so."""
    if not isinstance(key, dict):
        return key
    try:
        if type(key) is not dict or any(type(n) is not str or type(v) not in _PLAIN for n, v in key.items()):
            raise ValueError('not plain data')
        return dict(key)
    except Exception:
        raise Refusal('bad-key', f'{where}: must be a public key, as plain data.') from None


class NoAnswer(Exception):
    """A signer that gave no answer in the time the stub writer gives it."""

    def __init__(self, ms):
        super().__init__(f'no answer within {ms} milliseconds')
        self.ms = ms


def _same_key(a, b):
    """Two public keys that have passed check_key: the same key, member for
    member. Only plain text is compared, so that no value can say that it
    equals another."""
    return len(a) == len(b) and all(type(n) is str and type(v) is str and n in a and type(a[n]) is str and str.__eq__(a[n], v) for n, v in b.items())


def _bytes_of(given):
    """The signature bytes a signer gave, copied, or None where it gave anything else."""
    if isinstance(given, (bytes, bytearray, memoryview)):
        try:
            return bytes(given)
        except Exception:
            return None
    return None


def _take_item(item, alg, where, expected):
    """Read one item of "private_keys" for the method of its place."""
    if _platform_key(item, alg):
        return {'platform': True, 'item': item, 'sign': lambda data: sign(alg, item, data)}
    try:
        key = getattr(item, 'key', None)
        fn = getattr(item, 'sign', None)
    except Exception:
        raise Refusal('bad-field', f'{where}: could not be read.') from None
    if not callable(fn) or key is None:
        raise Refusal('bad-field', f'{where}: {_signer_shape(alg)}')
    key = _plain_key(key, f'{where}.key')
    check_key(key, [alg], f'{where}.key')
    label = f'the {alg} key {thumbprint(key)}'
    if expected is not None and not _same_key(key, expected):
        raise Refusal('bad-key', f'{where}: the signer holds {label}, which is not the key this record must be signed with ({thumbprint(expected)}).')
    # Nothing is signed that this device cannot check: so a signer for a
    # method it does not have built in is refused before any signer is asked.
    if not method_available(alg):
        raise Refusal('bad-key', f'{where}: this device does not have {alg} built in, so it cannot check a signature from the signer for {label}. No record was made.')
    return {'platform': False, 'item': item, 'key': key, 'call': fn, 'sign': lambda data: _signer_signature(fn, key, alg, label, where, data)}


def _signer_signature(fn, key, alg, label, where, data):
    """One signature from a signer, checked before it is used."""
    def failed(why):
        return Refusal('signature-invalid', f'{where}: the signer for {label} {why} No record was made.')

    data = bytes(data)
    try:
        given = fn(data)
    except NoAnswer as e:
        raise failed(f'gave no answer within {e.ms} milliseconds.') from None
    except Exception as e:
        raise failed('failed with an error.') from e
    if inspect.isawaitable(given):
        close = getattr(given, 'close', None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
        raise failed('gave a coroutine, which was not run: "sign" must be an ordinary function that gives bytes.')
    signature = _bytes_of(given)
    if signature is None:
        raise failed('gave something other than bytes.')
    if alg in _SIGNATURE_BYTES and len(signature) != _SIGNATURE_BYTES[alg]:
        raise failed(f'gave a signature of {len(signature)} bytes, where an {alg} signature is {_SIGNATURE_BYTES[alg]}.')
    # Whether the method is built in was settled before any signer was
    # asked; a signature that cannot be checked even so is not used.
    state = verify_signature(key, signature, data)
    if state != 'valid':
        raise failed('gave a signature that does not check against its key: it holds another key, or signed other bytes.')
    return signature


def _take_items(private_keys, methods, expected):
    """Read every item of "private_keys", one for each method, before anything is signed."""
    if not isinstance(private_keys, (list, tuple)):
        raise Refusal('bad-field', f'privateKeys: must be a list, one private key or signer for each of {", ".join(methods)}.')
    taken = []
    for i, alg in enumerate(methods):
        try:
            item = private_keys[i] if i < len(private_keys) else None
        except Exception:
            raise Refusal('bad-field', f'privateKeys[{i}]: could not be read.') from None
        taken.append(_take_item(item, alg, f'privateKeys[{i}]', expected[i] if expected is not None else None))
    return taken


def signing_keys(private_keys, methods, expected=None):
    """The functions that sign, one for each method, for a writer that signs
    now. Keys sign as they always did; each signer is read and checked as
    set out above. "expected": the public keys the record must be signed
    with, where the writer knows them."""
    return [t['sign'] for t in _take_items(private_keys, methods, expected)]


class _Held:
    """A signer as a writer that holds its keys keeps it: its key read once,
    and each signature asked for through the writer."""

    __slots__ = ('key', '_sign')

    def __init__(self, key, sign_):
        self.key = key
        self._sign = sign_

    def sign(self, data):
        return self._sign(data)

    def __repr__(self):
        return '<a signer held by a stub writer>'


def hold_signing_keys(private_keys, methods, expected, run):
    """For a writer that holds its keys, such as the stub writer: the list to
    use in place of "private_keys". Keys are kept as they are. Each signer is
    read once, here, and checked against the key the records must be signed
    with where that is known; in its place stands one whose signatures are
    asked for through run(sign, data), which gives the answer or raises
    NoAnswer."""
    held = []
    for t in _take_items(private_keys, methods, expected):
        if t['platform']:
            held.append(t['item'])
        else:
            held.append(_Held(dict(t['key']), lambda data, call=t['call']: run(call, data)))
    return held


def answer_within(call, data, ms, context=None):
    """Ask call(data) in a thread of its own, and wait "ms" milliseconds at
    most. After that NoAnswer is raised, and whatever it gives later is not
    used. "context", if given, is the contextvars context it runs in."""
    answer = concurrent.futures.Future()

    def job():
        try:
            answer.set_result(call(data))
        except Exception as e:  # handed on, and named by the writer
            answer.set_exception(e)
        except BaseException as e:  # noqa: BLE001
            # SystemExit, KeyboardInterrupt and the like, raised in the signer's own thread, are a failure like any other.
            answer.set_exception(RuntimeError(f'the signer raised {type(e).__name__}'))

    target = (lambda: context.run(job)) if context is not None else job
    threading.Thread(target=target, daemon=True, name='provared-sign').start()
    done, _ = concurrent.futures.wait([answer], timeout=ms / 1000)
    if not done:
        raise NoAnswer(ms)
    return answer.result()


class _KeySigner:
    """A private key held in memory, as a signer (signer_from_key)."""

    __slots__ = ('_alg', '_private', 'key')

    def __init__(self, alg, private_key, key):
        self._alg = alg
        self._private = private_key
        self.key = key

    def sign(self, data):
        return sign(self._alg, self._private, data)

    def __repr__(self):
        return f'<a signer for an {self._alg} key held in memory>'


def signer_from_key(alg, private_key, key):
    """Wrap a private key held in memory as a signer, so that a key in memory
    and a key held elsewhere take one path. alg: 'Ed25519' or 'ML-DSA-87';
    private_key: a private key of the package "cryptography" for that
    method; key: its public key, in one of the shapes of the format
    description, section 3.8. SLH-DSA is not built into "cryptography", so
    it is refused here, as write_seal refuses it."""
    if alg == SLH:
        raise RuntimeError('SLH-DSA is not built into this device.')
    if alg not in ('Ed25519', 'ML-DSA-87'):
        raise Refusal('bad-field', f'alg: must be Ed25519, ML-DSA-87 or {SLH}.')
    kind = ed25519.Ed25519PrivateKey if alg == 'Ed25519' else (_mldsa.MLDSA87PrivateKey if _mldsa is not None else None)
    if kind is None or not isinstance(private_key, kind):
        raise Refusal('bad-field', f'private_key: must be a private key for {alg}, of the package "cryptography".')
    key = _plain_key(key, 'key')
    check_key(key, [alg], 'key')
    return _KeySigner(alg, private_key, key)


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
