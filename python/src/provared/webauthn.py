# Checking a passkey signature (a Web Authentication assertion), later and
# offline. The steps are those of W3C Web Authentication Level 3, section
# 7.2 ("Verifying an Authentication Assertion"), as far as they apply
# without a server session: format description, section 4.4.

import hmac

from . import _js
from .encoding import Refusal, from_utf8, sha256, to_base64url, utf8
from .signatures import verify_signature

# The flags byte of the authenticator data (Web Authentication, section 6.1).
_FLAG_USER_PRESENT = 0x01
_FLAG_USER_VERIFIED = 0x04
_FLAG_ATTESTED_DATA = 0x40
_FLAG_EXTENSION_DATA = 0x80


def _bad_data(why):
    return Refusal('passkey-bad-data', why)


def ecdsa_der_to_raw(der):
    """A passkey returns an ES256 signature in ASN.1 DER form (Web
    Authentication, section 6.5.5). This gives the two numbers side by side,
    32 bytes each, and refuses any DER that is not strictly encoded."""
    der = bytes(der)
    # SEQUENCE, short-form length (two 33-byte INTEGERs at most: 70 bytes).
    if len(der) < 8 or len(der) > 72 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise _bad_data('The passkey signature is not a well-formed ECDSA signature.')
    out = bytearray(64)
    at = 2
    for part in range(2):
        if at + 2 > len(der) or der[at] != 0x02:
            raise _bad_data('The passkey signature is not a well-formed ECDSA signature.')
        length = der[at + 1]
        start = at + 2
        end = start + length
        if length < 1 or length > 33 or end > len(der):
            raise _bad_data('The passkey signature is not a well-formed ECDSA signature.')
        # A positive whole number in its shortest form.
        if der[start] & 0x80:
            raise _bad_data('The passkey signature holds a negative number.')
        if length > 1 and der[start] == 0x00 and not (der[start + 1] & 0x80):
            raise _bad_data('The passkey signature is not in its shortest form.')
        digits = der[start + 1:end] if der[start] == 0x00 else der[start:end]
        if len(digits) > 32:
            raise _bad_data('The passkey signature holds a number that is too large.')
        out[part * 32 + (32 - len(digits)):part * 32 + 32] = digits
        at = end
    if at != len(der):
        raise _bad_data('The passkey signature has bytes left over.')
    return bytes(out)


def check_assertion(key, rp_id, origin, signed_bytes, authenticator_data, client_data_json, signature, without=()):
    """Check a passkey signature over some bytes.

    Returns 'valid', or 'unavailable' when this device cannot check the
    passkey's signing method. Raises a Refusal with a code that says which
    check failed.
    """
    try:
        client = _js.parse(from_utf8(client_data_json, 'passkey-bad-data'))
    except (Refusal, ValueError):
        raise _bad_data("The passkey's client data is not JSON.") from None
    if not isinstance(client, dict):
        raise _bad_data("The passkey's client data is not an object.")

    # This must be an answer to "sign", not to "create a passkey".
    if client.get('type') != 'webauthn.get' or not isinstance(client.get('type'), str):
        raise Refusal('passkey-wrong-type', 'The passkey answer was not made for signing.')
    # The challenge is the hash of the bytes that had to be signed.
    challenge = to_base64url(sha256(signed_bytes))
    if not (isinstance(client.get('challenge'), str) and client['challenge'] == challenge):
        raise Refusal('passkey-challenge-mismatch', 'The passkey signed something other than this slip.')
    # The page it was used on.
    if not (isinstance(client.get('origin'), str) and client['origin'] == origin) or client.get('crossOrigin') is True:
        raise Refusal('passkey-origin-mismatch', 'The passkey was used on a page other than the one the slip names.')

    # The authenticator data: which website, and the two flags.
    authenticator_data = bytes(authenticator_data)
    if len(authenticator_data) < 37:
        raise _bad_data("The passkey's authenticator data is cut short.")
    rp_id_hash = sha256(utf8(rp_id))
    if not hmac.compare_digest(authenticator_data[:32], rp_id_hash):
        raise Refusal('passkey-rpid-mismatch', 'The passkey belongs to a website other than the one the slip names.')
    flags = authenticator_data[32]
    if not (flags & _FLAG_USER_PRESENT):
        raise Refusal('passkey-user-not-present', 'The passkey did not record that a person was present.')
    if not (flags & _FLAG_USER_VERIFIED):
        raise Refusal('passkey-user-not-verified', 'The device did not confirm the person by fingerprint, face or PIN.')
    # An answer to "sign" never carries a new passkey's data, and carries
    # further bytes only when it says so.
    if flags & _FLAG_ATTESTED_DATA:
        raise _bad_data("The passkey's authenticator data holds data that belongs to creating a passkey.")
    if not (flags & _FLAG_EXTENSION_DATA) and len(authenticator_data) != 37:
        raise _bad_data("The passkey's authenticator data has bytes left over.")

    # The signature covers the authenticator data followed by
    # the hash of the client data.
    signed = authenticator_data + sha256(client_data_json)
    raw = ecdsa_der_to_raw(signature) if key['alg'] == 'ES256' else signature
    state = verify_signature(key, raw, signed, without)
    if state == 'invalid':
        raise Refusal('signature-invalid', 'The passkey signature does not fit the key the slip names.')
    return state
