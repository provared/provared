# The shared test files in test-vectors/ at the top of the repository,
# written by the JavaScript library (tools/make-vectors.mjs): this library
# must give every stored answer.

import json
import pathlib
import unittest

import answers_book
import answers_records
import answers_stamps
from provared import _js
from provared.encoding import count_characters, from_base64url, parse_canonical, parse_time, problem_from
from provared.jws import parse_record
from provared.keys import check_key, thumbprint
from provared.slip import _UNDEFINED, _plain_origin, check_slip
from provared.stub import validate_countersignature_content, validate_stub_content
from provared.webauthn import ecdsa_der_to_raw

ROOT = pathlib.Path(__file__).resolve().parents[2] / 'test-vectors'


def _answer(work):
    try:
        return {'ok': work()}
    except Exception as e:
        return {'refused': problem_from(e)}


def _true(check):
    def run(content):
        check(content)
        return True

    return run


def _record(c):
    p = parse_record(c['record'], c['kind'])
    return {'kind': p.kind, 'fingerprint': p.fingerprint, 'content': p.content, 'signatures': len(p.signatures)}


def _key(c):
    alg = check_key(c['key'], c['allowed'], 'key')
    return {'alg': alg, 'thumbprint': thumbprint(c['key'])}


ANSWER = {
    'parseCanonical': lambda c: _answer(lambda: parse_canonical(c['text'])),
    'fromBase64url': lambda c: _answer(lambda: from_base64url(c['text']).hex()),
    'parseTime': lambda c: {'ok': parse_time(c['text'])},
    'countCharacters': lambda c: {'ok': count_characters(c['text'])},
    'checkKey': lambda c: _answer(lambda: _key(c)),
    'ecdsaDerToRaw': lambda c: _answer(lambda: ecdsa_der_to_raw(bytes.fromhex(c['der'])).hex()),
    'parseRecord': lambda c: _answer(lambda: _record(c)),
    'validateStubContent': lambda c: _answer(lambda: _true(validate_stub_content)(c['content'])),
    'validateCountersignatureContent': lambda c: _answer(lambda: _true(validate_countersignature_content)(c['content'])),
    'plainOrigin': lambda c: {'ok': _plain_origin(c['text']) is not None},
    'checkSlip': lambda c: {'ok': check_slip(c['record'], c.get('options'), c['disclosures'] if 'disclosures' in c else _UNDEFINED)},
    **answers_stamps.ANSWER,
    **answers_records.ANSWER,
    **answers_book.ANSWER,
}


def _json_values(value):
    """As JSON.stringify writes a value: NaN and the infinities become null."""
    if isinstance(value, float) and (value != value or value in (float('inf'), float('-inf'))):
        return None
    if isinstance(value, dict):
        return {k: _json_values(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_values(v) for v in value]
    return value


def _plain(value):
    """The answer as JSON would carry it: whole numbers written as floats
    compare as whole numbers, as in JavaScript."""
    return _js.parse(json.dumps(_json_values(value), ensure_ascii=False))


def _read(path):
    # The files are read as JSON.parse reads them, so that a text such as
    # "\ud800" keeps its lone surrogate.
    return _js.parse(path.read_text(encoding='utf-8'))


class SharedTestFiles(unittest.TestCase):
    def test_every_file(self):
        files = sorted(ROOT.glob('*.json'))
        self.assertTrue(files, 'no shared test files found')
        for path in files:
            data = _read(path)
            answer = ANSWER.get(data['function'])
            if answer is None:
                self.fail(f'{path.name}: no Python answer for "{data["function"]}"')
            for c in data['cases']:
                with self.subTest(file=path.name, case=c['name']):
                    self.assertEqual(_plain(answer(c)), _plain(c['expected']))


if __name__ == '__main__':
    unittest.main()
