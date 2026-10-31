# The commands the person runs, as "hermes provared <command>" once the
# plugin is enabled (or, with the package installed by pip, as
# "python -m provared_hermes <command>"):
#
#   init                     make the agent's keys if they are missing, and print a link that opens
#                            the signing page with a starting permission filled in
#   use <file>               put a signed permission (the slip.json the signing page saves) in place;
#                            Hermes takes it in at its next tool call. The first "use" writes the
#                            list of the passkeys the plugin trusts, with this permission's
#   use <file> --new-passkey the same, for a permission signed with a new passkey of the person's own,
#                            which is added to that list
#   cancel <file>            put a signed cancellation (the cancellation.json the signing page saves)
#                            in place; Hermes takes it into the book at its next tool call, and its
#                            agent then acts no more under the permission it cancels
#   status                   what the folder holds, and the checker's answer for the book, against the
#                            passkeys on the list

import argparse
import json
import sys

from provared import check_book, from_base64url

from .folder import Folder, FolderError, _Lock, signing_link, starting_permission

DESCRIPTION = 'The agent\'s keys, the permission it acts under, and the book of its tool calls.'


def setup(parser):
    subs = parser.add_subparsers(dest='provared_command')
    subs.add_parser('init', help='Make the agent\'s keys, and print the link to sign a permission')
    use = subs.add_parser('use', help='Put a signed permission (slip.json) in place')
    use.add_argument('file', help='The file the signing page saved')
    use.add_argument('--new-passkey', action='store_true', help='The permission is signed with a new passkey of your own')
    cancel = subs.add_parser('cancel', help='Put a signed cancellation (cancellation.json) in place')
    cancel.add_argument('file', help='The file the signing page saved')
    subs.add_parser('status', help='What the folder holds, and the checker\'s answer for the book')


def _say(*lines):
    for line in lines:
        print(line)


def _init(folder):
    keys = folder.make_keys()
    _say(f'The folder: {folder.path}',
         f'The agent\'s keys are in {folder.keys_file}. Never share that file.',
         '',
         'Open this link, check the permission, and sign it with your passkey:',
         signing_link(starting_permission(keys)),
         '',
         'Then put the saved file in place:',
         '  hermes provared use <the saved slip.json>')
    return 0


def _use(folder, file, new_passkey):
    fingerprint, issuer = folder.use(file, new_passkey=new_passkey)
    content = json.loads(from_base64url(folder.placed_slip()['payload']).decode('utf-8'))
    _say(f'The permission {fingerprint} is in place, signed by the passkey {issuer}.',
         f"It runs from {content['validFrom']} until {content['validUntil']}.",
         'Hermes takes it in at its next tool call.')
    return 0


def _cancel(folder, file):
    folder.cancel(file)
    _say(f'The cancellation is in place, as {folder.cancellation_file}.',
         'Hermes takes it into the book at its next tool call; from then on its agent acts no more under the permission it cancels.')
    return 0


def _status(folder):
    _say(f'The folder: {folder.path}')
    try:
        folder.agent_keys()
        _say('The agent\'s keys: in place.')
    except FolderError as e:
        _say(str(e))
    try:
        trusted = folder.read_trusted() or []
    except FolderError as e:
        _say(str(e))
        trusted = []
    # Worked out first: Python 3.11, which this plugin supports, does not
    # allow a backslash inside an f-string's braces.
    named = ', '.join(trusted) or 'none yet (the first "use" names one)'
    _say(f'The passkeys this plugin trusts: {named}.')
    try:
        slip = folder.placed_slip()
        content = json.loads(from_base64url(slip['payload']).decode('utf-8'))
        _say(f"The permission in place: for \"{content['agent']['name']}\", from {content['validFrom']} until {content['validUntil']}.")
    except (FolderError, ValueError, KeyError) as e:
        _say(str(e))
    if folder.cancellation_file.exists():
        _say(f'A cancellation is in place: {folder.cancellation_file}.')
    lock = _Lock(folder.lock_file)
    if folder.path.exists():
        if lock.acquire():
            lock.release()
            _say('The book is not held by any program now.')
        else:
            _say('The book is held by a program now (Hermes).')
    if not folder.book_file.exists():
        _say('There is no book yet: it is made at the first tool call.')
        return 0
    text = folder.book_file.read_text(encoding='utf-8')
    # Checked against the passkeys on the list, never against those the book names itself.
    summary = check_book(text, issuer_keys=trusted)['summary']
    counts = summary['counts']
    _say(f"The book: {counts['slips']} permission(s), {counts['stubs']} receipt(s).",
         f"Intact, against the passkeys on the list, as far as this device can check: {'yes' if summary['intact'] else 'no'}.",
         f"Within the permission: {'yes' if summary['withinSlips'] else 'no'}.",
         'To check it on another device: npx provared-check <book.jsonl> --issuer <your passkey\'s thumbprint>')
    return 0


def run(args, folder_path=None):
    """Run a command; gives the exit code."""
    folder = Folder(folder_path)
    command = getattr(args, 'provared_command', None)
    try:
        if command == 'init':
            return _init(folder)
        if command == 'use':
            return _use(folder, args.file, args.new_passkey)
        if command == 'cancel':
            return _cancel(folder, args.file)
        if command == 'status':
            return _status(folder)
    except FolderError as e:
        print(str(e), file=sys.stderr)
        return 1
    print('Usage: hermes provared init | use <file> [--new-passkey] | cancel <file> | status', file=sys.stderr)
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m provared_hermes', description=DESCRIPTION)
    parser.add_argument('--folder', help='The folder of the agent\'s keys, permission and book (Hermes\'s data folder for the plugin by default)')
    setup(parser)
    args = parser.parse_args(argv)
    return run(args, args.folder)
