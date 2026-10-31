# The files the plugin keeps, in one folder, as the recorder beside Claude
# Code keeps them (integrations/claude-code in the repository):
#
#   agent-keys.jwk           the agent's two private keys (never share)
#   trusted-passkeys.json    the thumbprints of the passkeys whose permissions the plugin takes:
#                            written at the first "use", added to only by "use --new-passkey"
#   slip.json                the signed slip the agent acts under, from the signing page
#   slip-<fingerprint>.json  each slip of the book that stood in its place before, kept by its fingerprint
#   cancellation.json        a signed cancellation of a slip, from the signing page, if any
#   book.jsonl               the book: the slips and a stub for each tool call
#   book.lock                held by the one program that writes to the book
#
# By default the folder is Hermes's own data folder for the plugin,
# <Hermes home>/plugin-data/provared, which follows the active profile: each
# profile is an agent of its own, with its own keys and book.
#
# Nothing here reaches the network.

import json
import logging
import os
import re
import sys
import threading
from pathlib import Path

from provared import (
    check_slip,
    entry_line,
    fingerprint,
    from_base64url,
    key_set_from_seeds,
    key_set_seeds,
    open_recorder,
    thumbprint,
    to_base64url,
)
from provared.encoding import now_ms, parse_time
from provared.signatures import generate_key_set

__all__ = ['Folder', 'FolderError', 'default_folder', 'starting_permission', 'signing_link', 'SIGNING_PAGE']

SIGNING_PAGE = 'https://sign.prova.red/'
PLUGIN = 'provared'
_THUMBPRINT = re.compile(r'[A-Za-z0-9_-]{43}')


class FolderError(Exception):
    """Something in the folder stops the plugin from recording: no keys, no
    slip, a slip that does not pass its checks, a book that another program
    holds. The message says what to do."""


def default_folder():
    """Hermes's data folder for this plugin, in the active profile."""
    try:
        from plugins.plugin_storage import plugin_data_dir
        return Path(plugin_data_dir(PLUGIN))
    except Exception:  # Hermes is not importable here: its default home
        home = os.environ.get('HERMES_HOME') or str(Path.home() / '.hermes')
        return Path(home) / 'plugin-data' / PLUGIN


# --- keys kept between runs, as JSON Web Keys, in the same form as the recorder beside Claude Code ---

def _public(private_keys_jwk):
    ed, ml = private_keys_jwk
    return [{'alg': 'Ed25519', 'crv': 'Ed25519', 'kty': 'OKP', 'x': ed['x']}, {'alg': 'ML-DSA-87', 'kty': 'AKP', 'pub': ml['pub']}]


def _write_private(path, text):
    """Write a file only its owner may read (on Windows, the folder's own rights apply)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(text.encode('utf-8'))


def _replace(path, text):
    """Replace a small file (never the book) through a temporary one beside it.
    On Windows the replacement is refused while another program holds the file
    open, so it is tried again for up to two seconds."""
    tmp = f'{path}.tmp'
    with open(tmp, 'wb') as f:
        f.write(text.encode('utf-8'))
    for attempt in range(100):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 99:
                raise
            threading.Event().wait(0.02)


class _Lock:
    """An exclusive lock on book.lock, held by this process until released.
    The system releases it when the process ends, however it ends."""

    def __init__(self, path):
        self._path = path
        self._file = None

    def acquire(self):
        f = open(self._path, 'a+b')
        try:
            if sys.platform == 'win32':
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            return False
        self._file = f
        return True

    def release(self):
        f, self._file = self._file, None
        if f is None:
            return
        try:
            if sys.platform == 'win32':
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        finally:
            f.close()


def _slip_from(text, where):
    """A slip as it is kept in a file: the record the signing page saves, or a book line that holds one."""
    try:
        value = json.loads(text)
    except ValueError:
        raise FolderError(f'{where} is not JSON. It should be the file the signing page saves (slip.json).') from None
    if isinstance(value, dict) and list(value) == ['slip']:
        value = value['slip']
    if not isinstance(value, dict) or not isinstance(value.get('payload'), str):
        raise FolderError(f'{where} does not hold a signed permission (a slip). It should be the file the signing page saves (slip.json).')
    return value


def _slip_fingerprint(slip):
    return fingerprint(from_base64url(slip['payload']))


def _issuer_of(slip):
    content = json.loads(from_base64url(slip['payload']).decode('utf-8'))
    return thumbprint(content['issuer']['key'])


def _stat(path):
    try:
        s = path.stat()
    except OSError:
        return None
    return (s.st_mtime_ns, s.st_size)


def _slips_in(text):
    """The slips a book holds, in their order, read from its lines: a line that
    holds only a slip starts with {"slip": in the one canonical form."""
    found = []
    for line in text.split('\n'):
        if not line.startswith('{"slip":'):
            continue
        try:
            found.append(json.loads(line)['slip'])
        except (ValueError, KeyError, TypeError):
            pass  # not a slip that can be read: the checker reports it
    return found


def _passkeys_in(text):
    found = []
    for slip in _slips_in(text):
        try:
            key = _issuer_of(slip)
        except Exception:  # noqa: BLE001 -- not a slip that can be read: the checker reports it
            continue
        if key not in found:
            found.append(key)
    return found


def _stub_times(text, slip_fp):
    """The times of the stubs of the agent's own chain under a slip, by action,
    in milliseconds, read from the book's lines (the book passed its check
    when the writer was opened)."""
    times = {}
    for line in text.split('\n'):
        if not line.startswith('{"stub":'):
            continue
        try:
            content = json.loads(from_base64url(json.loads(line)['stub']['payload']).decode('utf-8'))
        except Exception:  # noqa: BLE001 -- not a stub that can be read: the checker reports it
            continue
        if content.get('slip') == slip_fp and 'pass' not in content:
            when = parse_time(content.get('when'))
            if when is not None:
                times.setdefault(content.get('action'), []).append(when)
    return times


class Folder:
    """The folder of one agent: its keys, its permissions and its book."""

    def __init__(self, path=None):
        self.path = Path(path) if path is not None else default_folder()
        self.keys_file = self.path / 'agent-keys.jwk'
        self.trusted_file = self.path / 'trusted-passkeys.json'
        self.slip_file = self.path / 'slip.json'
        self.cancellation_file = self.path / 'cancellation.json'
        self.book_file = self.path / 'book.jsonl'
        self.lock_file = self.path / 'book.lock'

    # --- keys ---

    def make_keys(self):
        """Make the agent's keys, if the file does not exist. Gives back the public key set."""
        if not self.keys_file.exists():
            self.path.mkdir(parents=True, exist_ok=True)
            _, private_keys = generate_key_set()
            ed_seed, ml_seed = key_set_seeds(private_keys)
            public, _ = key_set_from_seeds(ed_seed, ml_seed)
            jwks = [{'alg': 'Ed25519', 'crv': 'Ed25519', 'kty': 'OKP', 'x': public[0]['x'], 'd': to_base64url(ed_seed)},
                    {'alg': 'ML-DSA-87', 'kty': 'AKP', 'pub': public[1]['pub'], 'priv': to_base64url(ml_seed)}]
            _write_private(self.keys_file, json.dumps({'about': 'The private keys of the agent recorded by Provared. Never share this file.', 'keys': jwks}))
        return self.agent_keys()[0]

    def agent_keys(self):
        """The agent's public key set and private keys, from the file."""
        if not self.keys_file.exists():
            raise FolderError(f'There are no agent keys in {self.path}. Make them first: hermes provared init')
        try:
            jwks = json.loads(self.keys_file.read_text(encoding='utf-8'))['keys']
            public, private_keys = key_set_from_seeds(from_base64url(jwks[0]['d']), from_base64url(jwks[1]['priv']))
        except Exception:
            raise FolderError(f'The agent keys in {self.keys_file} cannot be read.') from None
        if public != _public(jwks):
            raise FolderError(f'The agent keys in {self.keys_file} do not match their own public parts.')
        return public, private_keys

    # --- the passkeys the plugin trusts ---
    #
    # A list of thumbprints in its own file (trusted-passkeys.json), written at
    # the first "use" and added to only by "use --new-passkey", as the recorder
    # beside Claude Code keeps it. The plugin takes a slip only from a passkey on
    # the list, and records nothing while the book or slip.json holds a slip from
    # any other. This raises the bar for a program that edits the folder; it
    # does not close it, because any program on this computer, the agent
    # included, can change this file too. The evidence that holds is a checker
    # naming the person's own passkey.

    def read_trusted(self):
        """The list, or None where the folder has none."""
        if not self.trusted_file.exists():
            return None
        try:
            listed = json.loads(self.trusted_file.read_text(encoding='utf-8-sig'))['passkeys']
        except Exception:  # noqa: BLE001
            listed = None
        if not isinstance(listed, list) or not listed or not all(isinstance(k, str) and _THUMBPRINT.fullmatch(k) for k in listed):
            raise FolderError(f'{self.trusted_file} does not hold a list of passkey thumbprints as {{"passkeys": ["..."]}}, '
                              'so the plugin trusts no passkey and records nothing.')
        return list(dict.fromkeys(listed))

    def write_trusted(self, listed):
        self.path.mkdir(parents=True, exist_ok=True)
        _replace(self.trusted_file, json.dumps({
            'about': 'The thumbprints of the passkeys whose permissions this plugin takes. Written by "use", '
                     'added to only by "use --new-passkey".',
            'passkeys': listed}, indent=2) + '\n')

    def trust_for(self, text, placed_issuer):
        """The passkeys trusted, for a book and the slip in place. Where the
        folder has no list: a new book trusts the passkey of its first slip; a
        book whose slips are all from one passkey (and slip.json too) is taken as
        it is; and the list is written. Then every slip in the book, and
        slip.json, must be from a passkey on the list."""
        listed = self.read_trusted()
        in_book = _passkeys_in(text)
        if listed is None:
            everyone = list(dict.fromkeys([*in_book, *([placed_issuer] if placed_issuer else [])]))
            if len(everyone) > 1:
                raise FolderError(f'The book and slip.json hold permissions signed by {len(everyone)} passkeys ({", ".join(everyone)}), '
                                  f'and the folder has no list of the passkeys this plugin trusts ({self.trusted_file}). If each of them '
                                  'is yours, write their thumbprints into that file as {"passkeys": ["...", "..."]}.')
            if not everyone:
                return []
            listed = everyone
            self.write_trusted(listed)
        foreign = [k for k in in_book if k not in listed]
        if foreign:
            raise FolderError(f'The book holds a permission signed by a passkey that is not on the list of passkeys this plugin '
                              f'trusts ({", ".join(foreign)}): it was not taken by "use" or "use --new-passkey", so the plugin '
                              'records nothing. Check the book with the checker, naming your own passkey (--issuer).')
        if placed_issuer and placed_issuer not in listed:
            raise FolderError(f'The permission in place (slip.json) is signed by a passkey ({placed_issuer}) that is not on the '
                              f'list of passkeys this plugin trusts ({", ".join(listed)}), so the plugin records nothing. If you '
                              'made a new passkey yourself, put the permission in place with: hermes provared use <file> --new-passkey')
        return listed

    # --- slips ---

    def placed_slip(self):
        """The slip in slip.json. A missing, empty or unreadable file is no permission."""
        if not self.slip_file.exists():
            raise FolderError(f'There is no signed permission at {self.slip_file}, so no recorded tool call is run. Sign one on '
                              'the signing page and put it in place: hermes provared use <the saved file>')
        return _slip_from(self.slip_file.read_text(encoding='utf-8-sig'), str(self.slip_file))

    def placed_cancellation(self):
        """The entry in cancellation.json, as a check takes it ({"cancellation": record}), or None."""
        if not self.cancellation_file.exists():
            return None
        where = self.cancellation_file
        try:
            value = json.loads(where.read_text(encoding='utf-8-sig'))
        except ValueError:
            raise FolderError(f'{where} is not JSON, so the plugin records nothing until it is put right or taken away. '
                              'It should be the file the signing page saves (cancellation.json).') from None
        if isinstance(value, dict) and isinstance(value.get('payload'), str):
            value = {'cancellation': value}
        if not isinstance(value, dict) or not isinstance(value.get('cancellation'), dict):
            raise FolderError(f'{where} does not hold a signed cancellation, so the plugin records nothing until it is put '
                              'right or taken away.')
        return value

    def stamp(self):
        """What tells whether the person changed what the plugin acts under: the
        time and size of slip.json, cancellation.json and the list of trusted
        passkeys."""
        return tuple(_stat(path) for path in (self.slip_file, self.cancellation_file, self.trusted_file))

    def check_new_slip(self, slip, agent_keys, trusted, new_passkey=False, now=None):
        """Check a slip before it is taken into the book: its passkey signature,
        that it names this folder's agent keys, that it has not ended, and that
        its passkey is on the list of trusted passkeys, unless that list is empty
        (a new book) or new_passkey says the person made a new passkey. Gives back
        the slip's fingerprint and the thumbprint of its passkey."""
        check = check_slip(slip)
        if check['problems']:
            words = ' '.join(f"[{p['code']}] {p['message']}" for p in check['problems'])
            raise FolderError(f'The permission does not pass its check, so it is not used: {words}')
        if check['signature']['state'] != 'valid':
            raise FolderError('This device could not check the passkey\'s signature on the permission, so it is not used.')
        content = check['content']
        if content['agent']['keys'] != agent_keys:
            raise FolderError('The permission names other keys than the agent\'s keys in this folder, so it is not used. '
                              'Sign one with the keys that "hermes provared init" prints.')
        if parse_time(content['validUntil']) <= (now_ms() if now is None else now):
            raise FolderError(f"The permission ended at {content['validUntil']}, so it is not used. Sign a new one.")
        issuer = check['issuerKey']
        if trusted and issuer not in trusted and not new_passkey:
            raise FolderError(f'This permission is signed by a passkey ({issuer}) that is not on the list of passkeys this plugin '
                              f'trusts ({", ".join(trusted)}), so it is not used. If you made a new passkey yourself, put it in '
                              'place with: hermes provared use <file> --new-passkey')
        return check['fingerprint'], issuer

    def use(self, file, new_passkey=False):
        """Put a signed slip in place as slip.json, after its checks, keeping the
        one before beside it by its fingerprint where the book holds that one
        (a permission the agent acted under). The first "use" writes the list
        of trusted passkeys with this slip's; a slip from a passkey not on the
        list is taken only with new_passkey, which adds it. An earlier permission
        of the book is not put back: sign a new one."""
        slip = _slip_from(Path(file).read_text(encoding='utf-8-sig'), str(file))
        agent_keys = self.agent_keys()[0]
        text = self.book_file.read_text(encoding='utf-8') if self.book_file.exists() else ''
        listed = self.read_trusted()
        if listed is None:
            in_book = _passkeys_in(text)
            if len(in_book) > 1:
                raise FolderError(f'The book holds permissions signed by {len(in_book)} passkeys ({", ".join(in_book)}), and the '
                                  f'folder has no list of the passkeys this plugin trusts ({self.trusted_file}). If each of them is '
                                  'yours, write their thumbprints into that file as {"passkeys": ["...", "..."]}.')
            listed = in_book
        slip_fp, issuer = self.check_new_slip(slip, agent_keys, listed, new_passkey)
        in_book = [_slip_fingerprint(s) for s in _slips_in(text)]
        if slip_fp in in_book and slip_fp != in_book[-1]:
            raise FolderError('This permission is an earlier one of the book, not the latest, so it is not put back. '
                              'Sign a new permission instead.')
        if issuer not in listed:
            self.write_trusted([*listed, issuer])
        elif not self.trusted_file.exists():
            self.write_trusted(listed)
        try:
            before = self.placed_slip()
        except FolderError:
            before = None
        # The permission it replaces is kept beside it only where the book holds
        # it, so that a copy kept here is always one the agent acted under.
        if before is not None and _slip_fingerprint(before) in in_book:
            kept = self.path / f'slip-{_slip_fingerprint(before)}.json'
            if _slip_fingerprint(before) != slip_fp and not kept.exists():
                kept.write_text(json.dumps(before), encoding='utf-8')
        self.path.mkdir(parents=True, exist_ok=True)
        _replace(self.slip_file, json.dumps(slip))
        return slip_fp, issuer

    def cancel(self, file):
        """Put a signed cancellation in place as cancellation.json. Hermes takes
        it into the book at its next tool call, and its agent then acts no more
        under the permission it cancels."""
        source = Path(file)
        keep, self.cancellation_file = self.cancellation_file, source
        try:
            entry = self.placed_cancellation()
        finally:
            self.cancellation_file = keep
        if entry is None:
            raise FolderError(f'There is no file at {source}.')
        self.path.mkdir(parents=True, exist_ok=True)
        _replace(self.cancellation_file, json.dumps(entry))
        return entry

    # --- the book ---

    def open(self, previous=None):
        """Open the stub writer on the book, acting under slip.json, with the
        person's cancellation (cancellation.json) handed to it if there is one.
        slip.json must be the latest permission of the book, or a new one that
        passes its checks, from a passkey on the list of trusted passkeys; it is
        then taken in. The book is locked for this process; "previous" (an Opened
        from before) keeps the lock, and its writer's book is the book. Gives
        back an Opened."""
        lock = previous.lock if previous is not None else _Lock(self.lock_file)
        if previous is None:
            self.path.mkdir(parents=True, exist_ok=True)
            if not lock.acquire():
                raise FolderError(f'The book in {self.path} is held by another program (another Hermes session, the gateway, '
                                  'or a worker of the same profile). Only one may write to a book; this one records nothing, '
                                  'so its tool calls are not run.')
        try:
            stamp = self.stamp()
            slip = self.placed_slip()
            agent_keys, private_keys = self.agent_keys()
            if previous is not None:
                # The book as the writer holds it, which may hold lines not yet
                # written to the file (a write that failed); and the file as this
                # process last wrote it, against which any change by another
                # program is found.
                text = previous.writer.book()
                saved = previous._saved
            else:
                text = self.book_file.read_text(encoding='utf-8') if self.book_file.exists() else ''
                saved = text
                if text and not text.endswith('\n'):
                    text += '\n'
            try:
                issuer = _issuer_of(slip)
            except Exception:  # noqa: BLE001
                raise FolderError(f'{self.slip_file} does not hold a permission that can be read.') from None
            trusted = self.trust_for(text, issuer)
            # The list written just now is not a change made by the person.
            stamp = (stamp[0], stamp[1], _stat(self.trusted_file))
            slip_fp = _slip_fingerprint(slip)
            in_book = [_slip_fingerprint(s) for s in _slips_in(text)]
            if slip_fp in in_book:
                if slip_fp != in_book[-1]:
                    raise FolderError('The permission in place (slip.json) is an earlier one of the book, not the latest, so it is '
                                      'not used, and no recorded tool call is run. Put the latest one back, or sign a new one.')
            else:
                slip_fp, issuer = self.check_new_slip(slip, agent_keys, trusted)
                text += entry_line({'slip': slip}) + '\n'
            cancellation = self.placed_cancellation()
            try:
                writer = open_recorder(text, slip_fp, private_keys, trusted)
            except Exception as e:  # noqa: BLE001 -- the library's refusal, in its words
                raise FolderError(f'The book cannot be opened, so no recorded tool call is run: {getattr(e, "message", e)}') from None
            record = cancellation['cancellation'] if cancellation is not None else None
            if record is not None and not (isinstance(record.get('payload'), str) and record['payload'] in text):
                # Handed to "add", the person's cancellation is written into the
                # book now, with the agent's acknowledgement. Where it cannot be
                # written as it was handed over, the writer writes the
                # cancellation by itself (a faulty time-stamp beside it), or keeps
                # it and writes it later (one dated ahead of the clock); either
                # way it allows nothing more under the slip it cancels, and its
                # words say which. A cancellation that does not pass its check
                # (another passkey, a spoiled signature, a slip the book does not
                # hold) would stop nothing: then no recorded call is run at all
                # until it is put right or taken away.
                try:
                    writer.add(cancellation)
                except Exception as e:  # noqa: BLE001 -- the library's words, in Hermes's log or the refusal
                    message = getattr(e, 'message', e)
                    payload = record.get('payload')
                    held = isinstance(payload, str) and (payload in writer.book() or any(
                        isinstance(c, dict) and isinstance(c.get('cancellation'), dict) and c['cancellation'].get('payload') == payload
                        for c in writer.cancellations()))
                    if not held:
                        raise FolderError(f'The cancellation in {self.cancellation_file} does not pass its check ({message}), so no '
                                          'recorded tool call is run until it is put right or taken away.') from None
                    logging.getLogger(__name__).warning('Provared: the cancellation in %s: %s', self.cancellation_file, message)
            content = json.loads(from_base64url(slip['payload']).decode('utf-8'))
            opened = Opened(self, writer, lock, slip_fp, stamp, content, saved, _stub_times(text, slip_fp))
            opened.save()
            return opened
        except BaseException:
            if previous is None:
                lock.release()
            raise


class BookChanged(Exception):
    """The book file is not what this process wrote: another program changed it."""


class Opened:
    """The stub writer, open on the folder's book under one slip."""

    def __init__(self, folder, writer, lock, slip_fingerprint, stamp, content, saved, stub_times):
        self.folder = folder
        self.writer = writer
        self.lock = lock
        self.slip_fingerprint = slip_fingerprint
        self.stamp = stamp
        self.content = content
        self._saved = saved
        self._times = stub_times
        self.last_when = max((t for ts in stub_times.values() for t in ts), default=0)
        self.closed = False

    def count_limits(self, action):
        """The limits on how many of this action may be taken: (count, period in milliseconds or None)."""
        return [(limit['count'], limit['per'] * 1000 if isinstance(limit.get('per'), int) else None)
                for limit in self.content.get('limits') or []
                if isinstance(limit, dict) and limit.get('action') == action and isinstance(limit.get('count'), int)]

    def used(self, action, period, now):
        """How many stubs of this action the agent's chain holds under the slip, in the period up to now, or in all."""
        times = self._times.get(action, [])
        return len(times) if period is None else sum(1 for t in times if now - period < t <= now)

    def note_stub(self, action, when):
        self._times.setdefault(action, []).append(when)
        self.last_when = max(self.last_when, when)

    def save(self):
        """Write what the book gained to the file. A book only grows, so the new
        lines are appended: that works while another program (a backup, a virus
        scanner) reads the file. Where the file is not what this process wrote
        (another program changed it, or the plugin was loaded again and another
        writer now holds the book), nothing is written, and BookChanged is raised."""
        if self.closed:
            raise BookChanged('The plugin was unloaded or loaded again: this writer no longer holds the book.')
        text = self.writer.book()
        path = self.folder.book_file
        try:
            size = path.stat().st_size if path.exists() else 0
        except OSError:
            size = None
        # Checked whether or not there is anything to write, so that no call
        # runs while the file is not what this process wrote.
        if size != len(self._saved.encode('utf-8')) or not text.startswith(self._saved):
            raise BookChanged(f'The book file {path} is not what this process wrote: another program changed it.')
        if text == self._saved:
            return
        with open(path, 'ab') as f:
            f.write(text[len(self._saved):].encode('utf-8'))
        self._saved = text

    def close(self):
        self.closed = True
        self.lock.release()


def starting_permission(agent_keys):
    """A starting permission for a Hermes agent, for the signing page: the
    agent's public keys and name, the actions Hermes's own tools take, and
    limits a person can change on the page before signing (the same numbers as
    the recorder beside Claude Code's). Its times are left to the page, which
    sets them when it is opened."""
    return {
        'agent': {'name': 'Hermes Agent', 'keys': agent_keys},
        'actions': ['provared.data.read', 'provared.data.search', 'provared.data.change', 'provared.web.read',
                    'provared.code.run', 'provared.agent.instruct'],
        'limits': [
            {'action': 'provared.code.run', 'count': 500, 'per': 3600},
            {'action': 'provared.data.change', 'count': 500, 'per': 3600},
        ],
        'requires': [],
        'never': ['destroys', 'conceal', 'deceive', 'bypass', 'escalate', 'continue-after-stop'],
        'with': [],
        'purpose': 'Work with Hermes Agent on this computer.',
    }


def signing_link(permission, page=SIGNING_PAGE):
    """The signing page's address, with a starting permission in its fragment
    (the part after "#", which a browser never sends)."""
    return f"{page}#permission={to_base64url(json.dumps(permission, separators=(',', ':')).encode('utf-8'))}"
