# Shared test cases: how each kind of case is answered by this library.
# Whole books, Shows and the check before acting. The library is loaded
# only when a case is answered.

from provared.encoding import problem_from


def _answer(work):
    try:
        return {'ok': work()}
    except Exception as e:
        return {'refused': problem_from(e)}


def _check_book(c):
    from provared.book import check_book

    return {'ok': check_book(c['text'], c.get('options'))}


def _check_show(c):
    from provared.book import check_show

    return {'ok': check_show(c['show'], c.get('options'))}


def _make_show(c):
    from provared.book import make_show

    options = c.get('showOptions') or {}
    return _answer(lambda: make_show(c['text'], c['indexes'], seal=options.get('seal'), disclosures=options.get('disclosures')))


def _check_before(c):
    from provared.guard import check_before

    return {'ok': check_before(c['text'], c['proposal'], c.get('options'))}


ANSWER = {
    'checkBook': _check_book,
    'checkShow': _check_show,
    'makeShow': _make_show,
    'checkBefore': _check_before,
}
