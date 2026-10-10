# A development stand-in for a passkey, and a stub writer opened under a
# slip it signed: for trying the library in an evening, and for tests.
#
# It is NOT a passkey. Its private key is an ordinary key made in this
# process's memory, and no person confirmed anything. It returns the same
# three values a passkey returns (the authenticator data, the client data,
# the signature), in the forms the W3C Web Authentication standard sets
# out, so that every record it signs passes the checker exactly as a real
# one would. To keep such a record from being mistaken for a person's, the
# name of the issuer in every slip it signs ends with " (development)", and
# the checker shows that name beside the slip.
#
# A real slip is signed by the person, in a browser, with a real passkey:
# see the browser part of the JavaScript library and the checking page.
# Nothing here is part of the checker, and nothing here reaches the network.

import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .book import write_book
from .encoding import fingerprint, format_time, from_base64url, now_ms, sha256, to_base64url, utf8
from .keys import thumbprint
from .recorder import open_recorder
from .signatures import generate_key_set
from .slip import assemble_slip, prepare_slip

__all__ = ['DEVELOPMENT_MARK', 'DevelopmentPasskey', 'DevelopmentSlip', 'development_passkey', 'development_slip', 'development_recorder']

DEVELOPMENT_MARK = '(development)'
"""The words every development slip carries in its issuer's name."""

_RP_ID = 'localhost'
_ORIGIN = 'http://localhost'


class DevelopmentPasskey:
    """A development stand-in for a passkey (ES256, the method most passkeys
    use). It signs on this computer, for the page address http://localhost,
    which the format allows for development only. It is not a passkey."""

    def __init__(self):
        self._private = ec.generate_private_key(ec.SECP256R1())
        numbers = self._private.public_key().public_numbers()
        self.key = {'alg': 'ES256', 'crv': 'P-256', 'kty': 'EC',
                    'x': to_base64url(numbers.x.to_bytes(32, 'big')),
                    'y': to_base64url(numbers.y.to_bytes(32, 'big'))}
        self.rp_id = _RP_ID
        self.origin = _ORIGIN

    def sign(self, challenge):
        """The three values a passkey returns, for a challenge from
        prepare_slip, prepare_approval or prepare_cancellation: the
        authenticator data, the client data and the signature."""
        client_data_json = utf8(json.dumps({'type': 'webauthn.get', 'challenge': to_base64url(challenge),
                                            'origin': _ORIGIN, 'crossOrigin': False}, separators=(',', ':')))
        # Flags 0x05: "user present" and "user verified". Nobody was: this is a stand-in.
        authenticator_data = sha256(utf8(_RP_ID)) + bytes([0x05, 0, 0, 0, 1])
        signature = self._private.sign(authenticator_data + sha256(client_data_json), ec.ECDSA(hashes.SHA256()))
        return authenticator_data, client_data_json, signature


def development_passkey():
    """A development stand-in for a passkey."""
    return DevelopmentPasskey()


def _marked_name(name):
    given = name.strip() if isinstance(name, str) and name.strip() else 'Development passkey'
    return given if given.endswith(DEVELOPMENT_MARK) else f'{given} {DEVELOPMENT_MARK}'


class DevelopmentSlip:
    """What development_slip hands back: the signed slip, its fingerprint, a
    book holding the slip alone, the thumbprint of the stand-in passkey (to
    hand to a checker as the passkey you trust), the agent's keys and the
    stand-in passkey itself."""

    def __init__(self, slip, slip_fingerprint, book, issuer_keys, agent_keys, agent_private_keys, passkey):
        self.slip = slip
        self.slip_fingerprint = slip_fingerprint
        self.book = book
        self.issuer_keys = issuer_keys
        self.agent_keys = agent_keys
        self.agent_private_keys = agent_private_keys
        self.passkey = passkey
        self.writer = None


def development_slip(fields=None, **named):
    """A slip signed with a development stand-in for a passkey, and new keys
    for the agent. Give the slip's members as for prepare_slip, as one dict
    or as keyword arguments; "actions" is required. "issuer" and the agent's
    keys are filled in, and the issuer's name is made to end with
    " (development)". By default the slip runs from a minute ago for one
    day, holds no limits, names no other party, and its purpose says that
    it is for development."""
    given = {} if fields is None else fields
    if not isinstance(given, dict):
        raise TypeError('development_slip: give the members of the slip as a dict, with at least "actions".')
    given = {**given, **named}
    passkey = DevelopmentPasskey()
    agent_keys, agent_private_keys = generate_key_set()
    now = now_ms()
    issuer = given.get('issuer') if isinstance(given.get('issuer'), dict) else {}
    agent = given.get('agent') if isinstance(given.get('agent'), dict) else {}
    content = {
        'validFrom': format_time(now - 60_000),
        'validUntil': format_time(now + 24 * 3_600_000),
        'purpose': 'For development: a record made with a stand-in for a passkey, which no person signed.',
        'limits': [],
        'with': [],
        **given,
        'issuer': {'name': _marked_name(issuer.get('name')), 'key': passkey.key, 'rpId': passkey.rp_id, 'origin': passkey.origin},
        'agent': {'name': agent['name'] if isinstance(agent.get('name'), str) else 'Development agent', **agent, 'keys': agent_keys},
    }
    prepared = prepare_slip(content)
    slip = assemble_slip(prepared, *passkey.sign(prepared['challenge']))
    slip_fingerprint = fingerprint(from_base64url(slip['payload']))
    return DevelopmentSlip(slip, slip_fingerprint, write_book([{'slip': slip}]), [thumbprint(passkey.key)],
                           agent_keys, agent_private_keys, passkey)


def development_recorder(fields=None, more=None, **named):
    """The stub writer, opened under a development slip, in one call: the
    shortest way to a first record. The same as development_slip followed by
    open_recorder; "more" (a dict) is passed to open_recorder: "options",
    "now", "countersign_within". What it hands back has the writer as
    ".writer", beside everything development_slip gives."""
    made = development_slip(fields, **named)
    made.writer = open_recorder(made.book, made.slip_fingerprint, made.agent_private_keys, made.issuer_keys, **(more or {}))
    return made
