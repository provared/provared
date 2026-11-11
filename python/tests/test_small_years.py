# The years 0000 to 0099. JavaScript's Date.UTC reads a year from 0 to 99
# as 1900 to 1999, so the JavaScript library refuses a time-stamp's time
# in such a year, and this library refuses it too, with the same words. A
# record's own time is text with four digits for the year (format
# description, section 3.6), and there each of those years is the year it
# says, in both libraries. The shared test files (der-times.json and
# times.json) hold the same cases.

import unittest

from provared.der import read_element, time_of
from provared.encoding import Refusal, format_time, parse_time

DAY = 86400000


def read(tag, text):
    data = bytes([tag, len(text)]) + text.encode('ascii')
    return time_of(data, read_element(data, 0))


class SmallYears(unittest.TestCase):
    def test_a_time_stamps_time_in_the_years_0000_to_0099_is_refused_and_0100_is_read(self):
        for text in ['00000101000000Z', '00010101000000Z', '00500101000000Z', '00700101000000Z',
                     '00960229000000Z', '00990101000000Z', '00991231235959Z', '00991231235959.5Z']:
            with self.assertRaises(Refusal, msg=text) as caught:
                read(0x18, text)
            self.assertEqual(caught.exception.code, 'stamp-bad-data', text)
            self.assertEqual(
                caught.exception.message,
                'A time-stamp is not laid out as its standard sets out: a time names a moment that does not exist.',
                text,
            )
        self.assertEqual(read(0x18, '01000101000000Z'), -59011459200000)
        self.assertEqual(read(0x18, '19700101000000Z'), 0)
        # The short form has two digits for the year, and names 1950 to 2049.
        self.assertEqual(read(0x17, '500101000000Z'), parse_time('1950-01-01T00:00:00Z'))
        self.assertEqual(read(0x17, '491231235959Z'), parse_time('2049-12-31T23:59:59Z'))

    def test_a_records_time_in_the_years_0000_to_0099_is_read_as_it_is_written(self):
        self.assertEqual(parse_time('0000-01-01T00:00:00Z'), -62167219200000)
        self.assertEqual(parse_time('0001-01-01T00:00:00Z'), -62167219200000 + 366 * DAY)
        self.assertEqual(parse_time('0050-01-01T00:00:00Z'), -60589296000000)
        self.assertEqual(parse_time('0099-12-31T23:59:59Z'), -59011459201000)
        self.assertEqual(parse_time('0100-01-01T00:00:00Z'), -59011459200000)
        self.assertEqual(parse_time('0096-02-29T00:00:00Z'), parse_time('0096-03-01T00:00:00Z') - DAY)
        self.assertIsNone(parse_time('0099-02-29T00:00:00Z'))
        for text in ['0000-01-01T00:00:00Z', '0050-01-01T00:00:00Z', '0099-12-31T23:59:59Z']:
            self.assertEqual(format_time(parse_time(text)), text)
            self.assertLess(parse_time(text), parse_time('1900-01-01T00:00:00Z'), text)


if __name__ == '__main__':
    unittest.main()
