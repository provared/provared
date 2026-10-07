# Small checks on the fields of a record's content. Each raises a Refusal
# with the code "bad-field" and says which field and why.

import re

from . import _js
from .actions import is_unknown_reserved
from .encoding import MAX_NUMBER, Refusal, count_characters, from_base64url, parse_time


def fail(path, why):
    return Refusal('bad-field', f'{path}: {why}')


def members(value, required, optional, path):
    """An object must hold every required member, and no member that is neither
    required nor optional. An unknown member is refused."""
    if not isinstance(value, dict):
        raise fail(path, 'must be an object.')
    for name in required:
        if name not in value:
            raise fail(path, f'"{name}" is missing.')
    for name in value:
        if name not in required and name not in optional:
            raise fail(path, 'holds a member that is not known.')


def text(value, minimum, maximum, path):
    # The quick test on the raw length keeps a huge text from being counted.
    if not isinstance(value, str) or _js.utf16_length(value) > maximum * 2 or count_characters(value) < minimum or count_characters(value) > maximum:
        raise fail(path, f'must be text of {minimum} to {maximum} characters.')


def whole_number(value, path):
    if not _js.is_safe_integer(value) or value < 0 or value > MAX_NUMBER:
        raise fail(path, 'must be a whole number, 0 or more.')


def list_of(value, minimum, maximum, path):
    if not isinstance(value, list) or len(value) < minimum or len(value) > maximum:
        raise fail(path, f'must be a list of {minimum} to {maximum} items.')


_NAME = re.compile(r'[a-z0-9][a-z0-9._-]{0,63}')
_UNIT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,15}')


def short_name(value, path):
    """An action name, or the id of a service."""
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise fail(path, 'must be 1 to 64 lower-case letters, digits, full stops, hyphens or underscores.')


def action_name(value, path):
    """An action name. Names that begin "provared." must be on the shared list."""
    short_name(value, path)
    if is_unknown_reserved(value):
        raise fail(path, 'names that begin "provared." are reserved, and this one is not on the shared list.')


def unit(value, path):
    if not isinstance(value, str) or not _UNIT.fullmatch(value):
        raise fail(path, 'must be 1 to 16 letters, digits, full stops, hyphens or underscores, with no spaces.')


def label(value, path):
    """A label chosen by whoever wrote the record. Never checked against anything."""
    text(value, 1, 200, path)


def _base64url_of_length(value, length, path, what):
    try:
        decoded = from_base64url(value)
    except Refusal:
        raise fail(path, f'must be {what}.') from None
    if len(decoded) != length:
        raise fail(path, f'must be {what}.')


def id_(value, path):
    """A unique number: 16 bytes in base64url."""
    _base64url_of_length(value, 16, path, 'a unique number of 16 bytes in base64url')


def fingerprint_text(value, path):
    """A fingerprint: SHA-256 in base64url."""
    _base64url_of_length(value, 32, path, 'a SHA-256 fingerprint in base64url')


def time(value, path):
    """The time in milliseconds."""
    ms = parse_time(value)
    if ms is None:
        raise fail(path, 'must be a time written as YYYY-MM-DDTHH:MM:SSZ.')
    return ms
