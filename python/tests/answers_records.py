# Shared test cases: how each kind of case is answered by this library.
#
# The cases are those of test/helpers/vectors-records.mjs: the approval, the
# refusal, a service's terms, the cancellation, the acknowledgement, the
# vouching record, the withdrawal and the pass. Each answer has the shape the
# JavaScript answer has.

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from provared import approval, pass_, service, standing
from provared.encoding import from_base64url, problem_from, to_base64url
from provared.jws import signing_input
from provared.signatures import verify_signature


def _answer(work):
    try:
        return {'ok': work()}
    except Exception as e:
        return {'refused': problem_from(e)}


def _valid(check):
    """A content check: true, or why it was refused."""

    def run(c):
        check(c['content'])
        return True

    return lambda c: _answer(lambda: run(c))


def _prepared(prepare):
    """What a passkey record's preparation gives, with its bytes in hexadecimal."""

    def run(c):
        p = prepare(c['fields'])
        return {
            'contentBytes': p['contentBytes'].hex(),
            'payloadB64': p['payloadB64'],
            'protectedB64': p['protectedB64'],
            'challenge': p['challenge'].hex(),
            'fingerprint': p['fingerprint'],
        }

    return lambda c: _answer(lambda: run(c))


def _assembled(assemble):
    """A passkey record put together from a preparation and the passkey's three values."""

    def run(c):
        return assemble(c['prepared'], bytes.fromhex(c['authenticatorData']), bytes.fromhex(c['clientDataJSON']), bytes.fromhex(c['signature']))

    return lambda c: _answer(lambda: run(c))


def _written(write):
    """A record written and signed: its content, its fingerprint and its
    Ed25519 signature exactly, and whether its ML-DSA-87 signature checks.
    The Ed25519 key is fixed by the case; the ML-DSA-87 key is made afresh."""

    def run(c):
        ed = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['seed']))
        ml = mldsa.MLDSA87PrivateKey.generate()
        ml_key = {'alg': 'ML-DSA-87', 'kty': 'AKP', 'pub': to_base64url(ml.public_key().public_bytes_raw())}
        out = write(c['fields'], [ed, ml])
        record = out['record']
        first, second = record['signatures']
        check = verify_signature(ml_key, from_base64url(second['signature']), signing_input(second['protected'], record['payload']))
        return {'fingerprint': out['fingerprint'], 'payload': record['payload'], 'signatures': [first, {'protected': second['protected'], 'check': check}]}

    return lambda c: _answer(lambda: run(c))


ANSWER = {
    'validateApprovalContent': _valid(approval.validate_approval_content),
    'requestOf': lambda c: _answer(lambda: approval.request_of(c['content'])),
    'prepareApproval': _prepared(approval.prepare_approval),
    'assembleApproval': _assembled(approval.assemble_approval),
    'validateRefusalContent': _valid(service.validate_refusal_content),
    'validateTermsContent': _valid(service.validate_terms_content),
    'writeRefusal': _written(service.write_refusal),
    'writeTerms': _written(service.write_terms),
    'validateCancellationContent': _valid(standing.validate_cancellation_content),
    'validateAcknowledgementContent': _valid(standing.validate_acknowledgement_content),
    'validateVouchingContent': _valid(standing.validate_vouching_content),
    'validateWithdrawalContent': _valid(standing.validate_withdrawal_content),
    'prepareCancellation': _prepared(standing.prepare_cancellation),
    'assembleCancellation': _assembled(standing.assemble_cancellation),
    'writeAcknowledgement': _written(standing.write_acknowledgement),
    'writeVouching': _written(standing.write_vouching),
    'writeWithdrawal': _written(standing.write_withdrawal),
    'validatePassContent': _valid(pass_.validate_pass_content),
    'writePass': _written(pass_.write_pass),
    'recordConstants': lambda c: _answer(lambda: {'REFUSAL_REASONS': service.REFUSAL_REASONS, 'VOUCHED_KINDS': standing.VOUCHED_KINDS, 'MAX_PASSES': pass_.MAX_PASSES}),
}
