# A first record, in one file. Run it, then check what it wrote:
#
#   pip install provared
#   python first_record.py
#   npx provared-check book.jsonl --issuer <the thumbprint it prints>
#
# (The command-line checker is in the JavaScript package; in Python, check
# the book with check_book, as the last lines show.)
#
# The permission is signed with a DEVELOPMENT STAND-IN for a passkey: a key
# made in memory, which no person confirmed. Every slip it signs says so in
# its issuer's name, and the checker shows that name. A real permission is
# signed by a person, in a browser, with a real passkey.

from provared import check_book
from provared.dev import development_recorder

SEND = 'provared.message.send'

# A permission: the agent may send messages, at most two.
made = development_recorder({
    'actions': [SEND],
    'limits': [{'action': SEND, 'count': 2}],
    'purpose': 'Send a few messages, to make a first record.',
})

# Each action is asked for first, taken only if the slip allows it, and
# receipted after. The third message is outside the slip, so it is not sent.
for i in range(1, 4):
    outcome = made.writer.act({'action': SEND}, lambda i=i: print(f'message {i} sent'))
    if not outcome['done']:
        breach = outcome['answer']['breaches'][0]
        print(f"message {i} not sent: [{breach['code']}] {breach['message']}")

# The record: one line for the slip, then one for each receipt.
book = made.writer.book()
with open('book.jsonl', 'w', encoding='utf-8') as f:
    f.write(book)

# Checked here, naming the passkey you trust. The same answer as the
# command-line checker gives.
summary = check_book(book, issuer_keys=made.issuer_keys)['summary']
print(f"\nWritten: book.jsonl. Intact: {summary['intact']}. Within its slip: {summary['withinSlips']}.")
print(f'To check it with the command-line checker:\n  npx provared-check book.jsonl --issuer {made.issuer_keys[0]}')
