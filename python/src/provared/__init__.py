# Provared, draft version 0: proof of what an AI agent was allowed to do,
# and what it then did. Evidence, not a verdict.
#
# The Python version of the JavaScript library, built in stages. It gives
# the same answers, case for case, as the shared test files in
# test-vectors/ at the top of the repository show. One difference: the
# package "cryptography" has no SLH-DSA yet, so a seal's third signature is
# reported as not checked on this device, and never as a pass.
#
# Checking:  check_book, check_show, check_slip
#            open_checker (a checker that is carried on as the book grows)
#            check_before (would this action be outside the slip?)
# Writing:   prepare_slip + assemble_slip (the person, with a passkey),
#            prepare_approval + assemble_approval (the person's yes to one action),
#            write_stub (the agent), countersign, write_refusal, write_terms
#            (the service), block_stamp_item (a proof from a public
#            blockchain, to put beside a seal),
#            prepare_cancellation + assemble_cancellation (the person ends a slip),
#            write_acknowledgement (the agent's side says it was handed a cancellation),
#            write_vouching, write_withdrawal (an organisation vouches for a name),
#            write_pass (an agent hands part of its permission to a helper agent),
#            write_book, make_show
# Beside an agent: open_recorder (the stub writer: ask first, act, write
#            the receipt), record_tools (an agent's tools behind the stub
#            writer), arguments_fingerprint, NotTaken
# Keys:      generate_key_set, key_set_from_seeds, key_set_seeds, thumbprint,
#            key_set_fingerprint
# Names:     the shared list of actions, the kinds of action, the rules of conduct

from .actions import ACTION_KINDS, CONDUCT_RULES, RESERVED_PREFIX, SHARED_ACTIONS, action_kind
from .approval import assemble_approval, prepare_approval
from .blockstamp import block_fingerprint, block_stamp_item
from .book import LIMITS, check_book, check_show, entry_line, make_show, open_checker, write_book
from .compare import condition_words, limit_words, never_words
from .encoding import Refusal, fingerprint, format_time, from_base64url, random_id, sha256, to_base64url, utf8
from .guard import check_before
from .headers import MIN_BLOCKS_AFTER, blocks_in_chain, check_header_chain
from .keys import thumbprint
from .pass_ import write_pass
from .recorder import COUNTERSIGN_WITHIN_MS, Recorder, open_recorder
from .seal import key_set_fingerprint
from .service import REFUSAL_REASONS, write_refusal, write_terms
from .signatures import generate_key_set, key_set_from_seeds, key_set_seeds, method_available
from .slip import COVERABLE, assemble_slip, check_slip, prepare_slip
from .standing import VOUCHED_KINDS, assemble_cancellation, prepare_cancellation, write_acknowledgement, write_vouching, write_withdrawal
from .stub import countersign, write_stub
from .tools import NotTaken, arguments_fingerprint, record_tools

__all__ = [
    'MIN_BLOCKS_AFTER', 'blocks_in_chain', 'check_header_chain',
    'COUNTERSIGN_WITHIN_MS', 'NotTaken', 'Recorder', 'arguments_fingerprint', 'key_set_from_seeds', 'key_set_seeds', 'open_recorder',
    'record_tools',
    'ACTION_KINDS', 'CONDUCT_RULES', 'COVERABLE', 'LIMITS', 'REFUSAL_REASONS', 'RESERVED_PREFIX', 'SHARED_ACTIONS', 'VOUCHED_KINDS',
    'Refusal', 'action_kind', 'assemble_approval', 'assemble_cancellation', 'assemble_slip', 'block_fingerprint', 'block_stamp_item',
    'check_before', 'check_book', 'check_show', 'check_slip', 'condition_words', 'countersign', 'entry_line', 'fingerprint',
    'format_time', 'from_base64url', 'generate_key_set', 'key_set_fingerprint', 'limit_words', 'make_show', 'method_available',
    'never_words', 'open_checker', 'prepare_approval', 'prepare_cancellation', 'prepare_slip', 'random_id', 'sha256', 'thumbprint',
    'to_base64url', 'utf8', 'write_acknowledgement', 'write_book', 'write_pass', 'write_refusal', 'write_stub', 'write_terms',
    'write_vouching', 'write_withdrawal',
]
