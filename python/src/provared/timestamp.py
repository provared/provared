# Checking an outside time-stamp: a signed statement by a time-stamp
# service that some fingerprint existed at some time.
#
# The standard is RFC 3161 (the time-stamp), carried in the signed-data
# layout of RFC 5652, signed with a key named by an X.509 certificate
# (RFC 5280). Format description, section 21.
#
# The checker is told which services it trusts, by the fingerprint of each
# service's certificate. It follows no chain of certificates and asks no
# outside party: the person checking decides whom to trust.
#
# The service's signature is checked with the package "cryptography", which
# rests on OpenSSL as Node.js's Web Crypto does.

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .der import TAG, bad_stamp, children, content_of, ecdsa_to_raw, expect, hex_of, item, read_element, time_of, validate_der, whole_of
from .encoding import Refusal, format_time, sha256, to_base64url

MAX_STAMP_BYTES = 12288
"""The largest time-stamp, in bytes."""

MAX_ACCURACY_SECONDS = 300
"""The loosest a time-stamp may state its own time and still count, in seconds."""

# Object identifiers, as the hexadecimal of their DER content.
OID = {
    'signedData': '2a864886f70d010702',
    'tstInfo': '2a864886f70d0109100104',
    'contentType': '2a864886f70d010903',
    'messageDigest': '2a864886f70d010904',
    'signingCertificate': '2a864886f70d010910020c',
    'signingCertificateV2': '2a864886f70d010910022f',
    'sha1': '2b0e03021a',
    'sha256': '608648016503040201',
    'sha384': '608648016503040202',
    'sha512': '608648016503040203',
    'rsaEncryption': '2a864886f70d010101',
    'sha256WithRsa': '2a864886f70d01010b',
    'sha384WithRsa': '2a864886f70d01010c',
    'sha512WithRsa': '2a864886f70d01010d',
    'ecdsaWithSha256': '2a8648ce3d040302',
    'ecdsaWithSha384': '2a8648ce3d040303',
    'ecdsaWithSha512': '2a8648ce3d040304',
    'ecPublicKey': '2a8648ce3d0201',
    'p256': '2a8648ce3d030107',
    'p384': '2b81040022',
    'ed25519': '2b6570',
}

HASHES = {OID['sha256']: 'SHA-256', OID['sha384']: 'SHA-384', OID['sha512']: 'SHA-512'}
RSA_WITH = {OID['sha256WithRsa']: 'SHA-256', OID['sha384WithRsa']: 'SHA-384', OID['sha512WithRsa']: 'SHA-512'}
ECDSA_WITH = {OID['ecdsaWithSha256']: 'SHA-256', OID['ecdsaWithSha384']: 'SHA-384', OID['ecdsaWithSha512']: 'SHA-512'}

_HASHLIB = {'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512'}
_HASH_OBJECTS = {'SHA-256': hashes.SHA256, 'SHA-384': hashes.SHA384, 'SHA-512': hashes.SHA512}


def _invalid(why):
    return Refusal('stamp-invalid', why)


def _algorithm_of(data, element, what):
    """An "AlgorithmIdentifier": a sequence that begins with an object identifier."""
    expect(element, TAG.SEQUENCE, what)
    parts = children(data, element, 2)
    return {'oid': hex_of(data, expect(item(parts, 0), TAG.OID, what)), 'parameters': item(parts, 1)}


def _digest(name, data):
    return hashlib.new(_HASHLIB[name], bytes(data)).digest()


def _read_statement(data):
    """The statement the service signed (RFC 3161 section 2.4.2, "TSTInfo")."""
    outer = expect(read_element(data, 0), TAG.SEQUENCE, 'the statement')
    if outer.end != len(data):
        raise bad_stamp('the statement has bytes left over.')
    validate_der(data, outer)
    parts = children(data, outer, 10)
    version = expect(item(parts, 0), TAG.INTEGER, 'the version of the statement')
    if hex_of(data, version) != '01':
        raise bad_stamp('the statement is of a version other than 1.')
    expect(item(parts, 1), TAG.OID, 'the policy')
    imprint = children(data, expect(item(parts, 2), TAG.SEQUENCE, 'the fingerprint that was stamped'), 2)
    hash_oid = _algorithm_of(data, item(imprint, 0), 'the fingerprint method')['oid']
    stamped = content_of(data, expect(item(imprint, 1), TAG.OCTET_STRING, 'the fingerprint that was stamped'))
    expect(item(parts, 3), TAG.INTEGER, 'the serial number')
    time = time_of(data, expect(item(parts, 4), TAG.GENERALIZED_TIME, 'the time'))

    # What may follow, each at most once and in this order: how exact the
    # time is, whether stamps are strictly ordered, a number used once, the
    # service's name, and extensions.
    i = 5
    accuracy_seconds = 0
    if item(parts, i) is not None and parts[i].tag == TAG.SEQUENCE:
        for a in children(data, parts[i], 3):
            if a.tag == TAG.INTEGER:
                digits = content_of(data, a)
                if len(digits) > 4 or digits[0] & 0x80:
                    raise bad_stamp('the statement says how exact its time is in a way that cannot be read.')
                accuracy_seconds = 0
                for b in digits:
                    accuracy_seconds = accuracy_seconds * 256 + b
            elif a.tag != 0x80 and a.tag != 0x81:
                raise bad_stamp('the statement says how exact its time is in a way that cannot be read.')
        i += 1
    if item(parts, i) is not None and parts[i].tag == TAG.BOOLEAN:
        i += 1
    if item(parts, i) is not None and parts[i].tag == TAG.INTEGER:
        i += 1
    if item(parts, i) is not None and parts[i].tag == TAG.CONTEXT_0:
        i += 1
    critical = False
    if item(parts, i) is not None and parts[i].tag == TAG.CONTEXT_1:
        for extension in children(data, parts[i], 16):
            fields = children(data, expect(extension, TAG.SEQUENCE, 'an extension'), 3)
            if any(x.tag == TAG.BOOLEAN and x.start < len(data) and data[x.start] == 0xFF for x in fields):
                critical = True
        i += 1
    if i != len(parts):
        raise bad_stamp('the statement holds parts that are not in the order its standard sets out.')
    return {'hash': hash_oid, 'stamped': stamped, 'time': time, 'accuracySeconds': accuracy_seconds, 'critical': critical}


def _check_key_encoding(data, certificate, method, size=None):
    """The public key of a certificate, written exactly as its standard sets
    out, so that two checkers cannot disagree about whether it can be read:
    RSA as RFC 3279 section 2.3.1 sets out (the method's parameters empty,
    the key two positive whole numbers in strict DER, nothing after them);
    ECDSA as RFC 5480 section 2.2 (an uncompressed point of the named
    curve); Ed25519 as RFC 8410 section 4 (no parameters, 32 bytes). In each,
    the string of bits has no unused bits.

    An RSA key is 2,048 to 8,192 bits, with an odd public number from 3 to
    2^32 - 1: a small number, so that checking a signature cannot be made
    slow, and never 1, under which anyone can make a signature that checks."""
    why = 'the public key of a certificate is not written as its standard sets out.'
    key_bits = certificate['keyBits']
    if key_bits.end - key_bits.start < 1 or data[key_bits.start] != 0:
        raise bad_stamp(why)
    inner = bytes(data[key_bits.start + 1:key_bits.end])
    parameters = certificate['keyParameters']
    if method == 'ECDSA':
        if len(inner) != 1 + 2 * size or inner[0] != 0x04:
            raise bad_stamp(why)
        return
    if method == 'Ed25519':
        if parameters is not None or len(inner) != 32:
            raise bad_stamp(why)
        return
    if parameters is None or parameters.tag != TAG.NULL:
        raise bad_stamp(why)
    try:
        key = read_element(inner, 0)
        if key.tag != TAG.SEQUENCE or key.end != len(inner):
            raise ValueError
        validate_der(inner, key)
        parts = children(inner, key, 3)
        if len(parts) != 2 or parts[0].tag != TAG.INTEGER or parts[1].tag != TAG.INTEGER or inner[parts[0].start] & 0x80 or inner[parts[1].start] & 0x80:
            raise ValueError
        n, e = parts
    except Exception:
        raise bad_stamp(why) from None
    modulus = content_of(inner, n)
    if len(modulus) > 0 and modulus[0] == 0:
        modulus = modulus[1:]
    length = 0 if len(modulus) == 0 else (len(modulus) - 1) * 8 + modulus[0].bit_length()
    exponent = content_of(inner, e)
    if len(exponent) > 0 and exponent[0] == 0:
        exponent = exponent[1:]
    odd = len(exponent) > 0 and (exponent[-1] & 1) == 1
    if length < 2048 or length > 8192 or len(exponent) == 0 or len(exponent) > 4 or not odd or (len(exponent) == 1 and exponent[0] < 3):
        raise _invalid('A time-stamp was signed with an RSA key whose size or public number is not accepted.')


def _read_certificate(data, element):
    """What is needed from a certificate (RFC 5280 section 4.1): when it is in
    force, and its public key."""
    whole = whole_of(data, expect(element, TAG.SEQUENCE, 'a certificate'))
    tbs = expect(item(children(data, element, 3), 0), TAG.SEQUENCE, 'the body of a certificate')
    parts = children(data, tbs, 12)
    # The version, in [0], is absent only in the oldest kind of certificate.
    i = 1 if item(parts, 0) is not None and parts[0].tag == TAG.CONTEXT_0 else 0
    expect(item(parts, i), TAG.INTEGER, 'the serial number of a certificate')
    i += 1
    expect(item(parts, i), TAG.SEQUENCE, 'the signing method of a certificate')
    i += 1
    expect(item(parts, i), TAG.SEQUENCE, 'the issuer of a certificate')
    i += 1
    validity = children(data, expect(item(parts, i), TAG.SEQUENCE, 'the dates of a certificate'), 2)
    i += 1
    if len(validity) != 2:
        raise bad_stamp('a certificate does not hold two dates.')
    expect(item(parts, i), TAG.SEQUENCE, 'the subject of a certificate')
    i += 1
    key_info = expect(item(parts, i), TAG.SEQUENCE, 'the public key of a certificate')
    key_parts = children(data, key_info, 2)
    key_algorithm = _algorithm_of(data, item(key_parts, 0), 'the kind of public key')
    not_before = time_of(data, validity[0])
    not_after = time_of(data, validity[1])
    spki = whole_of(data, key_info)
    key_bits = expect(item(key_parts, 1), TAG.BIT_STRING, 'the public key of a certificate')
    parameters = key_algorithm['parameters']
    return {
        'whole': whole,
        'notBefore': not_before,
        'notAfter': not_after,
        'spki': spki,
        'keyOid': key_algorithm['oid'],
        'keyBits': key_bits,
        'curveOid': hex_of(data, parameters) if parameters is not None and parameters.tag == TAG.OID else None,
        'keyParameters': parameters,
    }


def _signing_certificate_of(data, value, v2):
    """The signed attribute that says which certificate signed (RFC 3161
    section 2.4.2; RFC 2634 and RFC 5035): the fingerprint method and the
    fingerprint of the certificate."""
    outer = children(data, expect(value, TAG.SEQUENCE, 'the signing certificate attribute'), 2)
    certs = children(data, expect(item(outer, 0), TAG.SEQUENCE, 'the signing certificate attribute'), 8)
    first = children(data, expect(item(certs, 0), TAG.SEQUENCE, 'the signing certificate attribute'), 3)
    at = 0
    hash_name = 'SHA-256' if v2 else 'SHA-1'
    if v2 and item(first, 0) is not None and first[0].tag == TAG.SEQUENCE:
        hash_name = HASHES.get(_algorithm_of(data, first[0], 'the signing certificate attribute')['oid'])
        if not hash_name:
            raise _invalid('A time-stamp names its certificate with a fingerprint method that is not accepted.')
        at = 1
    return {'hash': hash_name, 'value': content_of(data, expect(item(first, at), TAG.OCTET_STRING, 'the signing certificate attribute'))}


def _public_key(certificate):
    """The public key of a certificate, loaded for checking. It has already
    passed _check_key_encoding, so it is in the one strict form that
    "cryptography" reads, as Web Crypto reads it."""
    return serialization.load_der_public_key(bytes(certificate['spki']))


def _verify_with(certificate, data, signature_oid, digest_name, signature, signed, without):
    """Check the service's signature with the public key of its certificate.
    Returns "valid", "invalid", or "unavailable" where this device has no
    built-in support for the method. The fingerprint method is the one the
    signer names (RFC 5652 section 5.4); a signing method that names another
    is refused."""
    raw = signature
    curve = None
    if certificate['keyOid'] == OID['rsaEncryption']:
        if signature_oid != OID['rsaEncryption'] and RSA_WITH.get(signature_oid) != digest_name:
            return 'invalid'
        _check_key_encoding(data, certificate, 'RSA')
        method = 'RSA'
    elif certificate['keyOid'] == OID['ecPublicKey']:
        if certificate['curveOid'] == OID['p256']:
            curve = (ec.SECP256R1, 32)
        elif certificate['curveOid'] == OID['p384']:
            curve = (ec.SECP384R1, 48)
        if ECDSA_WITH.get(signature_oid) != digest_name or curve is None:
            return 'invalid'
        _check_key_encoding(data, certificate, 'ECDSA', curve[1])
        method = 'ECDSA'
        try:
            raw = ecdsa_to_raw(signature, curve[1])
        except Exception:
            return 'invalid'
    elif certificate['keyOid'] == OID['ed25519'] and signature_oid == OID['ed25519']:
        _check_key_encoding(data, certificate, 'Ed25519')
        method = 'Ed25519'
    else:
        return 'invalid'
    if any(isinstance(w, str) and w == method for w in without):
        return 'unavailable'
    try:
        key = _public_key(certificate)
    except Exception:
        return 'invalid'
    try:
        if method == 'RSA':
            if not isinstance(key, rsa.RSAPublicKey):
                return 'invalid'
            key.verify(signature, signed, padding.PKCS1v15(), _HASH_OBJECTS[digest_name]())
        elif method == 'ECDSA':
            # Web Crypto checks the two numbers side by side; "cryptography" takes them in DER.
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, curve[0]):
                return 'invalid'
            size = curve[1]
            der = encode_dss_signature(int.from_bytes(raw[:size], 'big'), int.from_bytes(raw[size:], 'big'))
            key.verify(der, signed, ec.ECDSA(_HASH_OBJECTS[digest_name]()))
        else:
            if not isinstance(key, ed25519.Ed25519PublicKey):
                return 'invalid'
            key.verify(signature, signed)
        return 'valid'
    except Exception:
        return 'invalid'


def check_stamp(token, fingerprint_bytes, options=None):
    """Check one time-stamp.

    token: the time-stamp, as the service returned it (the "TimeStampToken").
    fingerprint_bytes: the 32 bytes that must have been stamped.
    options: "trusted", the certificate fingerprints (SHA-256, base64url) of
    the services the checker trusts; "without", methods ("RSA", "ECDSA",
    "Ed25519") to treat as not built into this device.

    Returns {"state", "when", "time", "authority"}. "valid": signed by a
    service the checker trusts. "untrusted": signed soundly, by a service
    the checker did not name. "unavailable": this device cannot check the
    service's signing method; no time is given. "authority" is the
    fingerprint of the certificate that signed. "when" is the stated time,
    to the second, rounded down.

    Raises a Refusal: "stamp-bad-data", "stamp-wrong-data" or "stamp-invalid".

    """
    if not isinstance(options, dict):
        options = {}
    without = options.get('without') if isinstance(options.get('without'), list) else []
    if not isinstance(token, (bytes, bytearray)) or len(token) == 0 or len(token) > MAX_STAMP_BYTES:
        raise bad_stamp('it is empty, or larger than 12,288 bytes.')
    if not isinstance(fingerprint_bytes, (bytes, bytearray)):
        raise bad_stamp('there is no fingerprint to compare it with.')
    token = bytes(token)

    # The outer wrapper, and the signed data inside it (RFC 5652 sections 3
    # and 5.1). Every part is read, and must be strict DER.
    wrapper = expect(read_element(token, 0), TAG.SEQUENCE, 'the wrapper')
    if wrapper.end != len(token):
        raise bad_stamp('it has bytes left over.')
    validate_der(token, wrapper)
    outer = children(token, wrapper, 2)
    if len(outer) != 2 or hex_of(token, expect(outer[0], TAG.OID, 'the kind of content')) != OID['signedData']:
        raise bad_stamp('it is not signed data.')
    inner = children(token, expect(outer[1], TAG.CONTEXT_0, 'the signed data'), 1)
    parts = children(token, expect(item(inner, 0), TAG.SEQUENCE, 'the signed data'), 6)
    if hex_of(token, expect(item(parts, 0), TAG.INTEGER, 'the version')) != '03':
        raise bad_stamp('the signed data is of a version other than 3.')
    for method in children(token, expect(item(parts, 1), TAG.SET, 'the list of fingerprint methods'), 8):
        _algorithm_of(token, method, 'a fingerprint method')
    enclosed = children(token, expect(item(parts, 2), TAG.SEQUENCE, 'the enclosed content'), 2)
    if len(enclosed) != 2 or hex_of(token, expect(enclosed[0], TAG.OID, 'the kind of enclosed content')) != OID['tstInfo']:
        raise bad_stamp('what it encloses is not a time-stamp statement.')
    statement_holder = children(token, expect(enclosed[1], TAG.CONTEXT_0, 'the statement'), 1)
    statement_bytes = content_of(token, expect(item(statement_holder, 0), TAG.OCTET_STRING, 'the statement'))
    statement = _read_statement(statement_bytes)

    # The certificates, a list of withdrawn certificates (not used), and the one signer. Nothing else.
    following = 3
    certificates = []
    if item(parts, following) is not None and parts[following].tag == TAG.CONTEXT_0:
        for c in children(token, parts[following], 8):
            # Other kinds of certificate may sit here; only the ordinary kind is read.
            if c.tag == TAG.SEQUENCE:
                certificates.append(_read_certificate(token, c))
        following += 1
    if item(parts, following) is not None and parts[following].tag == TAG.CONTEXT_1:
        following += 1
    if following != len(parts) - 1:
        raise bad_stamp('the signed data holds parts that are not in the order its standard sets out.')
    signers = children(token, expect(parts[following], TAG.SET, 'the signer'), 1)
    signer = children(token, expect(item(signers, 0), TAG.SEQUENCE, 'the signer'), 7)
    # Version 1 names the certificate by its issuer and number; version 3 by its key.
    signer_version = hex_of(token, expect(item(signer, 0), TAG.INTEGER, 'the version of the signer'))
    second = item(signer, 1)
    if second is None or not ((signer_version == '01' and second.tag == TAG.SEQUENCE) or (signer_version == '03' and second.tag == 0x80)):
        raise bad_stamp('the signer is not named as its standard sets out.')
    digest_name = HASHES.get(_algorithm_of(token, item(signer, 2), "the signer's fingerprint method")['oid'])
    attributes = expect(item(signer, 3), TAG.CONTEXT_0, 'the signed attributes')
    signature_oid = _algorithm_of(token, item(signer, 4), 'the signing method')['oid']
    signature = content_of(token, expect(item(signer, 5), TAG.OCTET_STRING, 'the signature'))
    if len(signer) > 7 or (len(signer) == 7 and signer[6].tag != TAG.CONTEXT_1):
        raise bad_stamp('the signer holds parts that are not in the order its standard sets out.')

    # What was stamped must be the fingerprint the checker holds.
    if statement['hash'] != OID['sha256'] or statement['stamped'] != bytes(fingerprint_bytes):
        raise Refusal('stamp-wrong-data', 'A time-stamp was made for something else.')
    if statement['critical']:
        raise _invalid('A time-stamp carries an extension that it says must be understood, and this checker does not understand it.')
    if statement['accuracySeconds'] > MAX_ACCURACY_SECONDS:
        raise _invalid('A time-stamp states its time too loosely: to no better than more than 300 seconds.')

    # The signed attributes must name the statement (its kind and its
    # fingerprint, RFC 5652 section 5.4) and the certificate that signed
    # (RFC 3161 section 2.4.2).
    if not digest_name:
        raise _invalid('A time-stamp uses a fingerprint method that is not accepted.')
    kind_named = False
    digest_named = False
    named = None
    for attribute in children(token, attributes, 16):
        pair = children(token, expect(attribute, TAG.SEQUENCE, 'an attribute'), 2)
        name = hex_of(token, expect(item(pair, 0), TAG.OID, 'the name of an attribute'))
        values = children(token, expect(item(pair, 1), TAG.SET, 'the value of an attribute'), 4)
        if name == OID['contentType']:
            if kind_named or len(values) != 1 or values[0].tag != TAG.OID or hex_of(token, values[0]) != OID['tstInfo']:
                raise _invalid("A time-stamp's signature does not cover a time-stamp statement.")
            kind_named = True
        elif name == OID['messageDigest']:
            if digest_named or len(values) != 1 or values[0].tag != TAG.OCTET_STRING or content_of(token, values[0]) != _digest(digest_name, statement_bytes):
                raise _invalid("A time-stamp's signature does not cover its statement.")
            digest_named = True
        elif name == OID['signingCertificateV2'] or name == OID['signingCertificate']:
            if len(values) != 1:
                raise _invalid('A time-stamp does not say, in one way, which certificate signed it.')
            # Where both forms are present, the newer one is used.
            if named is None or name == OID['signingCertificateV2']:
                named = _signing_certificate_of(token, values[0], name == OID['signingCertificateV2'])
    if not kind_named or not digest_named:
        raise _invalid("A time-stamp's signature does not cover its statement.")
    if named is None:
        raise _invalid('A time-stamp does not say which certificate signed it.')

    # The one certificate the signed attributes name. A copy with the same
    # key and other contents has another fingerprint, and is not it.
    certificate = None
    for c in certificates:
        if _digest(named['hash'], c['whole']) == named['value']:
            certificate = c
            break
    if certificate is None:
        raise _invalid('A time-stamp does not carry the certificate it says signed it.' if certificates else 'A time-stamp carries no certificate to check it with.')

    # The signature covers the attributes, written as a set (RFC 5652 section
    # 5.4). The bytes are copied, so that the caller's time-stamp is not changed.
    signed = bytearray(whole_of(token, attributes))
    signed[0] = TAG.SET
    state = _verify_with(certificate, token, signature_oid, digest_name, signature, bytes(signed), without)
    if state == 'unavailable':
        return {'state': 'unavailable', 'when': None, 'time': float('nan'), 'authority': None}
    if state != 'valid':
        raise _invalid("A time-stamp's signature does not fit the certificate it names.")
    if statement['time'] < certificate['notBefore'] or statement['time'] > certificate['notAfter']:
        raise _invalid("A time-stamp is dated outside the time its service's certificate was in force.")
    authority = to_base64url(sha256(certificate['whole']))
    trusted = options.get('trusted')
    is_trusted = isinstance(trusted, list) and any(isinstance(t, str) and t == authority for t in trusted)
    return {'state': 'valid' if is_trusted else 'untrusted', 'when': format_time(statement['time']), 'time': statement['time'], 'authority': authority}
