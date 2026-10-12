from copy import deepcopy
import pytest
from analyzer.core.models import Instruction, AnalysisResult
from analyzer.core.field_references import field_references
from analyzer.app.jobs import Cancelled
from test_dex_browser import browser
from test_field_references import program, FIELD


def large_program():
    return program([Instruction(i * 2, 'sget' if i % 2 == 0 else 'sput', target=FIELD)
                    for i in range(603)])


def test_filtered_page_counts_and_offsets():
    p = large_program()
    page, links = field_references(p, FIELD, 'a', offset=600)
    assert page['total'] == 603 and page['shown'] == 3 and not page['has_more']
    assert links[0]['offset'] == 1200
    page, links = field_references(p, FIELD, 'a', offset=300, access='READ')
    assert page['total'] == 302 and page['shown'] == 2
    assert all(row['access'] == 'READ' for row in page['items'])
    assert [link['offset'] for link in links] == [1200, 1204]
    page, _ = field_references(p, FIELD, 'a', access='WRITE')
    assert page['total'] == 301 and page['has_more']
    page, links = field_references(p, FIELD, '', access='READ')
    assert page['total'] == 302 and not links


@pytest.mark.parametrize('kwargs', [dict(offset=-1), dict(offset=True), dict(access='EXECUTE')])
def test_invalid_page_requests(kwargs):
    with pytest.raises(ValueError):
        field_references(large_program(), FIELD, **kwargs)


@pytest.fixture
def paged(browser):
    w, wait = browser
    w._loaded(AnalysisResult('test.apk', '0' * 64, program=large_program(), notes={'keep': 'note'}))
    w.openDexClass('Lp/C;')
    wait()
    w.openDexEntry(1)
    wait()
    return w, wait


def test_gui_pages_filter_reset_and_boundaries(paged):
    w, wait = paged
    assert w.fieldPageLabel == '1–300 / 603 operands'
    assert w.fieldHasNext and not w.fieldHasPrevious
    w.nextFieldPage()
    w.nextFieldPage()  # Busy request ignored.
    wait()
    assert w.fieldPageLabel == '301–600 / 603 operands'
    w.nextFieldPage()
    wait()
    assert w.fieldPageLabel == '601–603 / 603 operands'
    assert not w.fieldHasNext
    w.nextFieldPage()
    assert not w.busy
    w.previousFieldPage()
    wait()
    assert w.fieldPageLabel == '301–600 / 603 operands'
    w.filterFieldReferences('READ')
    wait()
    assert w.fieldFilter == 'READ' and w.fieldPageLabel == '1–300 / 302 operands'
    w.nextFieldPage()
    wait()
    assert w.fieldPageLabel == '301–302 / 302 operands'
    w.filterFieldReferences('WRITE')
    wait()
    assert w.fieldFilter == 'WRITE' and w.fieldPageLabel == '1–300 / 301 operands'
    assert w._result.notes == {'keep': 'note'}


@pytest.mark.parametrize('failure', ['error', 'cancel', 'late_cancel', 'stale'])
def test_page_and_filter_failures_preserve_committed_state(paged, monkeypatch, failure):
    w, wait = paged
    before = deepcopy((w.content, w.navigationItems, w._field_page, w._location, w._history, w._result.notes))
    if failure in ('error', 'cancel'):
        def fail(*args, **kwargs):
            raise (Cancelled('cancel') if failure == 'cancel' else RuntimeError('failed'))
        monkeypatch.setattr('analyzer.gui.controllers.workspace.field_references', fail)
    else:
        def start(work, finish):
            w._busy = True
            w._finish_callback = finish
            value = work(None)
            if failure == 'late_cancel':
                w.cancel_token.cancel()
            else:
                w._field_selection = dict(w._field_selection)
            w._success(value)
        monkeypatch.setattr(w, '_start', start)
    w.filterFieldReferences('WRITE')
    wait()
    assert (w.content, w.navigationItems, w._field_page, w._location, w._history, w._result.notes) == before
    assert w.fieldFilter == 'ALL' and not w._field_pending


def test_empty_filtered_page_and_navigation_clears_page(paged):
    w, wait = paged
    for m in w._result.program.methods.values():
        for i in m.instructions:
            i.opcode = 'sget'
    w.filterFieldReferences('WRITE')
    wait()
    assert w.fieldPageLabel == '0–0 / 0 operands' and not w.navigationItems
    assert not w.fieldHasNext and not w.fieldHasPrevious
    w.showTab('Evidence')
    assert w._field_page is None
