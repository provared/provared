# A small demonstration world, shared by the examples. Everything in it is
# invented: the person, the agent, the supplier and the money. No real firm,
# person or payment is involved, and nothing is sent anywhere.
#
# The person's passkey here is a SOFTWARE STAND-IN, not a passkey: a key
# made in memory that returns the same three values a passkey returns, in
# the forms the Web Authentication standard sets out. It is for
# demonstration only. A real slip is signed by the person, in a browser,
# with a real passkey (see the browser part of the JavaScript library).
#
# The slip lets the agent order supplies from the invented supplier, up to
# 100 GBP in all, and send messages.

import contextlib
import ipaddress
import json
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from provared import (
    assemble_slip,
    fingerprint,
    format_time,
    from_base64url,
    generate_key_set,
    open_recorder,
    prepare_slip,
    sha256,
    thumbprint,
    to_base64url,
    utf8,
    write_book,
)
from provared.encoding import now_ms

ORDER = 'supplies.order'
MESSAGE = 'provared.message.send'
SUPPLIER = 'supplier'
LIMIT_GBP = 100

# The stand-in passkey's website: this computer, as in the library's own tests.
RP_ID = 'localhost'
ORIGIN = 'http://localhost:8787'


class StandInPasskey:
    """A software stand-in for a passkey (ES256), for demonstration only.
    It is not a passkey: its key is made in memory and confirms no person."""

    def __init__(self):
        self._private = ec.generate_private_key(ec.SECP256R1())
        numbers = self._private.public_key().public_numbers()
        self.key = {'alg': 'ES256', 'crv': 'P-256', 'kty': 'EC',
                    'x': to_base64url(numbers.x.to_bytes(32, 'big')),
                    'y': to_base64url(numbers.y.to_bytes(32, 'big'))}

    def sign(self, challenge):
        """The three values a passkey gives back: the authenticator data, the
        client data and the signature."""
        client_data_json = utf8(json.dumps({'type': 'webauthn.get', 'challenge': to_base64url(challenge),
                                            'origin': ORIGIN, 'crossOrigin': False}, separators=(',', ':')))
        # Flags 0x05: the person was present, and the device confirmed them.
        authenticator_data = sha256(utf8(RP_ID)) + bytes([0x05, 0, 0, 0, 1])
        signature = self._private.sign(authenticator_data + sha256(client_data_json), ec.ECDSA(hashes.SHA256()))
        return authenticator_data, client_data_json, signature


class World:
    """An invented person with a stand-in passkey, an agent with its two
    keys, a slip the person signed, and the stub writer on the book.

    orders and messages are what the invented supplier and the invented
    recipients received: the tools of the examples write into them, so a
    reader can see which calls were run."""

    def __init__(self):
        self.passkey = StandInPasskey()
        agent_keys, agent_private_keys = generate_key_set()
        now = now_ms()
        prepared = prepare_slip({
            'issuer': {'name': 'Sam Example (invented)', 'key': self.passkey.key, 'rpId': RP_ID, 'origin': ORIGIN},
            'agent': {'name': 'Office supplies agent (invented)', 'keys': agent_keys},
            'actions': [ORDER, MESSAGE],
            'limits': [{'action': ORDER, 'max': LIMIT_GBP, 'unit': 'GBP'}],
            'with': [{'id': SUPPLIER, 'name': 'Example Stationery (invented)'}],
            'validFrom': format_time(now - 60_000),
            'validUntil': format_time(now + 3_600_000),
            'purpose': 'Keep the office stocked with paper, pens and toner.',
        })
        self.slip = assemble_slip(prepared, *self.passkey.sign(prepared['challenge']))
        self.slip_fingerprint = fingerprint(from_base64url(self.slip['payload']))
        # Whoever checks the record names the passkey they trust, by its thumbprint.
        self.issuer_keys = [thumbprint(self.passkey.key)]
        # The stub writer: it asks the check before acting, runs an action
        # only if the slip allows it, and writes the stub.
        self.writer = open_recorder(write_book([{'slip': self.slip}]), self.slip_fingerprint,
                                    agent_private_keys, self.issuer_keys)
        self.orders = []
        self.messages = []


def order_amount(args):
    """The amount of an order, for the stub and for the check before acting."""
    return {'unit': 'GBP', 'value': args['total_gbp']}


def summary(check):
    """A short plain summary of a check of the book."""
    s = check['summary']
    return (f"The book checks as intact: {'yes' if s['intact'] else 'no'}. "
            f"The agent stayed within its slip: {'yes' if s['withinSlips'] else 'no'}. "
            f"Stubs in the book: {s['counts']['stubs']}.")


# --- nothing leaves this computer ---

_offline = [False]


def _refuse_the_network(event, args):
    if not _offline[0]:
        return
    if event == 'socket.getaddrinfo':
        host = args[0]
        if isinstance(host, bytes):
            host = host.decode('ascii', 'replace')
        if host is None or host == 'localhost' or _loopback(host):
            return
        raise ConnectionRefusedError(f'This example sends nothing to the network: a look-up of "{host}" was refused.')
    if event == 'socket.connect':
        address = args[1]
        host = address[0] if isinstance(address, tuple) and address else address
        if isinstance(host, str) and (host == 'localhost' or _loopback(host)):
            return
        raise ConnectionRefusedError(f'This example sends nothing to the network: a connection to {address!r} was refused.')


def _loopback(host):
    try:
        return ipaddress.ip_address(host.split('%')[0]).is_loopback
    except ValueError:
        return False


_hooked = [False]


@contextlib.contextmanager
def offline():
    """While it is open, any look-up of a name on the network, and any
    connection that Python's sockets make to anything but this computer,
    is refused. (Python's own event loop on Windows connects to this
    computer, so that is allowed.) The examples run inside it, to show that
    nothing is sent."""
    if not _hooked[0]:
        sys.addaudithook(_refuse_the_network)
        _hooked[0] = True
    _offline[0] = True
    try:
        yield
    finally:
        _offline[0] = False
