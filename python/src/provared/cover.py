# Covered fields: a record can be shown with some fields hidden, while its
# signatures still check. The method is the standard "Selective Disclosure
# for JSON Web Tokens" (RFC 9901), as it stands:
#
#   - a field to be covered is taken out of the signed content, and the
#     fingerprint of a "disclosure" is put in its place, in a list named
#     "_sd" (section 4.2.4.1);
#   - a disclosure is a salt (a random value), the field's name and its
#     value, written as a JSON list and then in base64url (section 4.2.1);
#   - the fingerprint is taken over the base64url text itself (section 4.2.3);
#   - to reveal the field, hand over the disclosure; to hide it, do not.
#
# Format description, section 24.

import re

from . import _js
from .encoding import Refusal, canonical_json, from_base64url, from_utf8, parse_canonical, random_id, sha256, to_base64url, utf8

MAX_DISCLOSURES = 64
"""The most disclosures one record may come with."""

_MAX_DEPTH = 12


def _bad(why):
    return Refusal('cover-invalid', f'A covered field is not as its standard sets out: {why}')


def disclosure_digest(disclosure):
    """The fingerprint of a disclosure: SHA-256 over the characters of its
    base64url text, written in base64url (RFC 9901, section 4.2.3)."""
    return to_base64url(sha256(utf8(disclosure)))


def make_disclosure(name, value, salt=None):
    """Make the disclosure for one member of an object (RFC 9901, section 4.2.1)."""
    if salt is None:
        salt = random_id()
    disclosure = to_base64url(utf8(canonical_json([salt, name, value])))
    return disclosure, disclosure_digest(disclosure)


def cover_members(obj, names):
    """Take the named members out of an object and leave the fingerprints of
    their disclosures in its "_sd" list, sorted, so that their order says
    nothing (RFC 9901, section 4.2.4.1). Returns the new object and the
    disclosures; the object handed in is not changed."""
    out = dict(obj)
    digests = list(out['_sd']) if isinstance(out.get('_sd'), list) else []
    disclosures = []
    for name in names:
        if name not in out:
            continue
        disclosure, digest = make_disclosure(name, out[name])
        del out[name]
        digests.append(digest)
        disclosures.append(disclosure)
    if digests:
        out['_sd'] = _js.sort_strings(digests)
    return out, disclosures


class _Given:
    __slots__ = ('parts', 'used')

    def __init__(self, parts):
        self.parts = parts
        self.used = False


def uncover(payload, disclosures=(), list_items=True, canonical=False):
    """Put back what the disclosures reveal, by the steps of RFC 9901, section
    7.1, step 3 to step 5.

    Returns (content, places, named): the content with every revealed field
    back in place and every "_sd" list, covered list item and "_sd_alg"
    removed; for each object that held an "_sd" list, by its path ("" for
    the top, "issuer", "with[0]"), how many fields are still covered there
    and which were revealed; and whether the content named its fingerprint
    method ("_sd_alg"). Raises a Refusal "cover-invalid".
    """
    if not isinstance(disclosures, (list, tuple)) or len(disclosures) > MAX_DISCLOSURES:
        raise _bad('the disclosures must be a list of at most 64.')
    # Each disclosure, by its fingerprint.
    given = {}
    for d in disclosures:
        if not isinstance(d, str) or len(d) == 0 or _js.utf16_length(d) > 87384:
            raise _bad('a disclosure must be text in base64url.')
        try:
            text = from_utf8(from_base64url(d), 'cover-invalid')
            parts = parse_canonical(text, 'cover-invalid') if canonical else _js.parse(text)
        except (Refusal, ValueError):
            raise _bad(
                'a disclosure is not JSON in the canonical form, written in base64url.' if canonical else 'a disclosure is not JSON written in base64url.'
            ) from None
        if not isinstance(parts, list) or len(parts) not in (2, 3) or not isinstance(parts[0], str):
            raise _bad('a disclosure must be a list of a salt and a value, or of a salt, a name and a value.')
        digest = disclosure_digest(d)
        if digest in given:
            raise _bad('a disclosure is handed over twice.')
        given[digest] = _Given(parts)

    seen = set()
    places = {}

    def once(digest):
        # A fingerprint is SHA-256 in base64url: 43 characters, and nothing else.
        data = None
        if isinstance(digest, str) and _js.utf16_length(digest) == 43:
            try:
                data = from_base64url(digest)
            except Refusal:
                data = None
        if data is None or len(data) != 32:
            raise _bad('a fingerprint in the content is not a SHA-256 fingerprint in base64url.')
        # Step 4: a fingerprint may appear only once in the whole content.
        if digest in seen:
            raise _bad('the same fingerprint appears twice in the content.')
        seen.add(digest)
        return given.get(digest)

    named = False

    def walk(value, path, depth):
        nonlocal named
        if depth > _MAX_DEPTH:
            raise _bad('the content is nested too deeply.')
        if isinstance(value, list):
            out = []
            for i, item in enumerate(value):
                if isinstance(item, dict) and len(item) == 1 and '...' in item:
                    if not list_items:
                        raise _bad('an item of a list may not be covered in this kind of record.')
                    found = once(item['...'])
                    # A covered list item with no disclosure is left out (step 3d).
                    if found is None:
                        continue
                    if len(found.parts) != 2:
                        raise _bad('the disclosure of a list item must hold a salt and a value.')
                    found.used = True
                    out.append(walk(found.parts[1], f'{path}[{i}]', depth + 1))
                else:
                    out.append(walk(item, f'{path}[{i}]', depth + 1))
            return out
        if not isinstance(value, dict):
            return value
        out = {}
        for name in _js.keys(value):
            member = value[name]
            if name == '_sd':
                continue
            if name == '_sd_alg':
                # The fingerprint method is named at the top only, and is SHA-256.
                if path != '' or member != 'sha-256' or not isinstance(member, str):
                    raise _bad('"_sd_alg" may stand only at the top, and must be "sha-256".')
                named = True
                continue
            out[name] = walk(member, name if path == '' else f'{path}.{name}', depth + 1)
        if '_sd' in value:
            if not isinstance(value['_sd'], list):
                raise _bad('"_sd" must be a list of fingerprints.')
            place = {'covered': 0, 'revealed': []}
            for digest in value['_sd']:
                found = once(digest)
                if found is None:
                    place['covered'] += 1
                    continue
                if len(found.parts) != 3:
                    raise _bad('the disclosure of a named field must hold a salt, a name and a value.')
                name = found.parts[1]
                if not isinstance(name, str) or name in ('_sd', '...', '_sd_alg'):
                    raise _bad('a disclosure names a field that may not be covered.')
                if name in out:
                    raise _bad('a disclosure names a field that is already there.')
                found.used = True
                out[name] = walk(found.parts[2], name if path == '' else f'{path}.{name}', depth + 1)
                place['revealed'].append(name)
            places[path] = place
        return out

    content = walk(payload, '', 0)
    # Step 5: every disclosure handed over must belong to this content.
    for d in given.values():
        if not d.used:
            raise _bad('a disclosure does not belong to this record.')
    return content, places, named
