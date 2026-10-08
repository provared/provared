# record_function: one ordinary function behind the stub writer, with its
# name, its parameters and its description kept (Python only).

import inspect
import unittest

from test_recorder import ORDER, World

from provared import NotTaken, Refusal, check_book, record_function


def place_order(item: str, value: int, note: str = '') -> str:
    """Order supplies from the supplier."""
    return f'ordered {item} for {value} GBP'


class RecordFunction(unittest.TestCase):
    def recorded(self, w, writer):
        return record_function(writer, place_order, ORDER, with_='supplier', amount=lambda args: {'unit': 'GBP', 'value': args['value']})

    def test_the_name_the_parameters_and_the_description_are_kept(self):
        w = World(limits=[{'action': ORDER, 'max': 200, 'unit': 'GBP'}])
        tool = self.recorded(w, w.open())
        self.assertEqual(tool.__name__, 'place_order')
        self.assertEqual(tool.__doc__, place_order.__doc__)
        self.assertEqual(inspect.signature(tool), inspect.signature(place_order))
        self.assertEqual(tool.__annotations__, place_order.__annotations__)

    def test_a_call_inside_the_slip_runs_and_leaves_a_stub_naming_its_arguments(self):
        w = World(limits=[{'action': ORDER, 'max': 200, 'unit': 'GBP'}])
        writer = w.open()
        tool = self.recorded(w, writer)
        self.assertEqual(tool('paper', 30), 'ordered paper for 30 GBP')
        self.assertEqual(tool(item='pens', value=20, note='blue'), 'ordered pens for 20 GBP')
        result = check_book(writer.book(), issuer_keys=w.issuer_keys)
        stubs = [e for e in result['entries'] if e['kind'] == 'stub']
        self.assertEqual(len(stubs), 2)
        self.assertEqual(stubs[0]['content']['details'][0]['name'], 'arguments')
        self.assertEqual(result['summary']['problemFound'], False)

    def test_a_call_outside_the_slip_is_not_run(self):
        w = World(limits=[{'action': ORDER, 'max': 50, 'unit': 'GBP'}])
        writer = w.open()
        tool = self.recorded(w, writer)
        with self.assertRaises(NotTaken):
            tool('a desk', 400)
        self.assertNotIn('"stub"', writer.book())

    def test_functions_that_cannot_be_recorded_so_are_refused(self):
        w = World()
        writer = w.open()

        async def later(item: str) -> str:
            return item

        def anything(*args, **kwargs):
            return None

        for run in (later, anything, 'not a function'):
            with self.assertRaises(Refusal) as refused:
                record_function(writer, run, ORDER)
            self.assertEqual(refused.exception.code, 'bad-field')


if __name__ == '__main__':
    unittest.main()
