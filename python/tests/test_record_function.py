# record_function: one ordinary function behind the stub writer, with its
# name, its parameters and its description kept (Python only).

import datetime
import enum
import inspect
import typing
import unittest

from test_recorder import ORDER, World

from provared import NotTaken, Refusal, arguments_fingerprint, check_book, fingerprint, record_function, record_tools, utf8
from provared import _js


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


class Size(int, enum.Enum):
    SMALL = 1


class Order(typing.TypedDict):
    item: str


class Model:
    pass


def stubs_of(w, writer):
    return [e['content'] for e in check_book(writer.book(), issuer_keys=w.issuer_keys)['entries'] if e['kind'] == 'stub']


class AfterTheThirdReview(unittest.TestCase):
    """The faults the third independent review of the Python version found."""

    def world(self):
        w = World(limits=[])
        return w, w.open()

    def test_a_whole_number_javascript_cannot_hold_exactly_is_refused(self):
        w, writer = self.world()
        received = []

        def delete_record(record: int) -> None:
            """Delete one record."""
            received.append(record)

        tool = record_function(writer, delete_record, ORDER)
        with self.assertRaises(Refusal) as refused:
            tool(2**60 + 1)
        self.assertEqual(refused.exception.code, 'bad-field')
        self.assertEqual((received, stubs_of(w, writer)), ([], []))
        # One that a float holds exactly is taken, with the fingerprint JavaScript gives it.
        tool(2**60)
        self.assertEqual(received, [2**60])
        self.assertEqual(stubs_of(w, writer)[0]['details'][0]['sha256'], arguments_fingerprint({'record': 2.0**60}))
        # JavaScript writes it with the fewest digits that read back as the same number.
        self.assertEqual(arguments_fingerprint({'n': 2**60}), fingerprint(utf8('{"n":1152921504606847000}')))
        # JSON is read as JavaScript reads it: a long whole number is the nearest float.
        self.assertEqual(_js.parse('9007199254740993'), 9007199254740992.0)
        self.assertEqual(_js.parse('-9007199254740991'), -9007199254740991)

    def test_a_number_of_a_class_built_on_int_is_written_as_its_value(self):
        w, writer = self.world()
        received = []

        def pick(size: Size) -> None:
            received.append(size)

        record_function(writer, pick, ORDER)(Size.SMALL)
        self.assertIs(received[0], Size.SMALL)
        self.assertEqual(stubs_of(w, writer)[0]['details'][0]['sha256'], fingerprint(utf8('{"size":1}')))

    def test_a_generator_function_is_refused(self):
        w, writer = self.world()

        def lines(item: str):
            yield item

        async def later_lines(item: str):
            yield item

        class Later:
            async def __call__(self, item: str) -> str:
                return item

        class Lines:
            def __call__(self, item: str):
                yield item

        for run in (lines, later_lines, Later(), Lines()):
            with self.subTest(run), self.assertRaises(Refusal) as refused:
                record_function(writer, run, ORDER)
            self.assertEqual(refused.exception.code, 'bad-field')
        for run in (lines, later_lines, Lines()):
            with self.subTest(run), self.assertRaises(Refusal) as refused:
                record_tools(writer, {'t': {'action': ORDER, 'run': run}})
            self.assertIn('generator function', refused.exception.message)
        self.assertEqual(stubs_of(w, writer), [])

    def test_a_parameter_that_can_never_be_plain_data_is_refused_when_recorded(self):
        w, writer = self.world()

        def by_model(order: Model) -> None: ...
        def by_date(when: datetime.datetime) -> None: ...
        def by_pair(pair: tuple[int, int]) -> None: ...
        def by_set(items: set[str]) -> None: ...
        def by_either(when: datetime.date | datetime.datetime) -> None: ...

        for run, name in ((by_model, 'order'), (by_date, 'when'), (by_pair, 'pair'), (by_set, 'items'), (by_either, 'when')):
            with self.subTest(run), self.assertRaises(Refusal) as refused:
                record_function(writer, run, ORDER)
            self.assertIn(f'"{name}"', refused.exception.message)

        # Where plain data can be given, or where it cannot be told, the function is taken.
        def plain(a: str, b: int, c: float, d: bool, e: list[int], f: dict[str, int], g: Order, h: Size,
                  i: datetime.date | None = None, j: typing.Any = None, k: object = None, m: 'Unknown' = None,  # noqa: F821
                  n: typing.Annotated[int, 'note'] = 0, o: typing.Literal['x'] = 'x') -> None: ...
        record_function(writer, plain, ORDER)

    def test_an_argument_that_is_not_plain_data_is_named(self):
        w, writer = self.world()

        def note(when=None) -> None: ...
        tool = record_function(writer, note, ORDER)
        with self.assertRaises(Refusal) as refused:
            tool(datetime.date(2026, 10, 8))
        self.assertIn('"when" is not (it is of the type date)', refused.exception.message)
        # A dict whose names are not all text is not plain data: 101 and "101" would become one.
        with self.assertRaises(Refusal) as refused:
            tool({101: 2, '101': 5})
        self.assertIn('"when" is not.', refused.exception.message)
        with self.assertRaises(Refusal):
            record_tools(writer, {'t': {'action': ORDER, 'run': lambda args: None}})['t']({1: 'a'})
        self.assertEqual(stubs_of(w, writer), [])

    def test_a_name_that_is_not_text_is_refused_in_plain_words(self):
        w, writer = self.world()

        class Tool:
            __name__ = 3

            def __call__(self, item: str) -> None: ...

        with self.assertRaises(Refusal) as refused:
            record_function(writer, Tool(), ORDER)
        self.assertIn('"__name__" must be text', refused.exception.message)

    def test_the_defaults_are_filled_in_and_the_function_is_handed_a_copy(self):
        w, writer = self.world()
        seen = []

        def collect(item: str, extras: list = [], count: int = 2) -> None:  # noqa: B006
            extras.append(item)
            seen.append(list(extras))

        tool = record_function(writer, collect, ORDER)
        mine = ['pens']
        tool('paper', mine)
        tool('toner')
        tool('ink')
        # Neither the caller's list nor the default changes from one call to the next.
        self.assertEqual((mine, seen), (['pens'], [['pens', 'paper'], ['toner'], ['ink']]))
        details = [s['details'][0]['sha256'] for s in stubs_of(w, writer)]
        self.assertEqual(details[1], arguments_fingerprint({'item': 'toner', 'extras': [], 'count': 2}))


if __name__ == '__main__':
    unittest.main()
