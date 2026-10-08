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
import weakref

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

refused = []
"""What offline() refused while it was open. The tests check that it stays
empty while an example runs, so that a refusal which a framework caught and
set aside still shows."""

# Sockets of this program that were given an address: a connection to this
# computer is allowed only to one of them. (Python's own event loop on
# Windows connects one of its sockets to another.) So nothing reaches a
# program on this computer that could pass it on, such as a proxy.
_bound = weakref.WeakSet()

_LOOK_UPS = ('socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostbyname_ex', 'socket.gethostbyaddr', 'socket.getnameinfo')
_SENDS = ('socket.connect', 'socket.sendto', 'socket.sendmsg')
_PROCESSES = ('subprocess.Popen', 'os.system', 'os.exec', 'os.spawn', 'os.posix_spawn', 'os.startfile')


def _refuse(what):
    refused.append(what)
    raise ConnectionRefusedError(f'This example sends nothing to the network: {what} was refused.')


def _host(value):
    if isinstance(value, tuple) and value:
        value = value[0]
    if isinstance(value, bytes):
        value = value.decode('ascii', 'replace')
    return value


def _loopback(host):
    if host == 'localhost':
        return True
    try:
        return isinstance(host, str) and ipaddress.ip_address(host.split('%')[0]).is_loopback
    except ValueError:
        return False


def _to_this_program(address):
    """Whether an address is that of a socket of this program."""
    if not (isinstance(address, tuple) and len(address) >= 2 and _loopback(_host(address))):
        return False
    for s in list(_bound):
        try:
            if s.fileno() != -1 and s.getsockname()[1] == address[1]:
                return True
        except OSError:
            pass
    return False


def _check(what, address):
    if _offline[0] and not _to_this_program(address):
        _refuse(f'{what} {address!r}')


def _refuse_the_network(event, args):
    if event == 'socket.bind':
        _bound.add(args[0])
        return
    if not _offline[0]:
        return
    if event in _LOOK_UPS:
        host = _host(args[0])
        if host is None or _loopback(host):
            return
        _refuse(f'a look-up of {host!r}')
    if event in _SENDS:
        address = args[1]
        if event == 'socket.sendmsg' and address is None:
            return  # on a socket already connected, which was checked then
        _check('a connection or a message to', address)
    if event in _PROCESSES:
        _refuse(f'starting a program ({event})')


def _guard_the_event_loop():
    """Python's event loop on Windows connects and sends through calls that
    raise no audit event. They are checked here instead."""
    if sys.platform != 'win32':
        return
    from asyncio import windows_events
    proactor = windows_events.IocpProactor
    connect, sendto = proactor.connect, proactor.sendto

    def checked_connect(self, conn, address):
        _check('a connection to', address)
        return connect(self, conn, address)

    def checked_sendto(self, conn, buf, flags=0, addr=None):
        if addr is not None:
            _check('a message to', addr)
        return sendto(self, conn, buf, flags, addr)

    proactor.connect, proactor.sendto = checked_connect, checked_sendto


# From the start, so that every socket of this program that is given an address is known.
sys.addaudithook(_refuse_the_network)
_guard_the_event_loop()


@contextlib.contextmanager
def offline():
    """While it is open, these are refused: any look-up of a name other than
    this computer's; any connection, or message, to anything but a socket
    of this same program; and starting another program. The examples run
    inside it, to show that nothing is sent."""
    _offline[0] = True
    try:
        yield
    finally:
        _offline[0] = False
