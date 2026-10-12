import os
import time
from copy import deepcopy

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import pytest
from PySide6.QtGui import QGuiApplication
from PySide6.QtTest import QTest
from analyzer.app.settings import Settings
from analyzer.core.models import AnalysisResult, Finding, Location
from analyzer.gui.controllers.workspace import Workspace
from conftest import ENTRY, HELPER


@pytest.fixture
def view(flow_program, monkeypatch):
    app = QGuiApplication.instance() or QGuiApplication([])
    workspace = Workspace(Settings())
    flow_program.methods[ENTRY].unit = 'dex-1'
    finding = Finding('r', 'Paging', '', 'WEBVIEW', location=Location(method=HELPER, offset=0))
    result = AnalysisResult('fixture.apk', '0' * 64, program=flow_program,
                            findings=[finding], notes={finding.id: 'unchanged'})
    workspace._loaded(result)
    workspace.selectFinding(0)
    workspace.findingLocation()
    monkeypatch.setattr(workspace, '_prepare_live_backend', lambda: None)
    calls = []
    def query(method, cancel, offset=0, limit=300):
        calls.append((method, offset, limit))
        return dict(offset=offset, total=603, evidence_origin='Synthetic JEB page',
                    items=[dict(address=ENTRY + '+14h', unit='dex-1')
                           for _ in range(min(limit, 603 - offset))])
    monkeypatch.setattr(workspace.app.backend, 'get_jeb_xrefs', query)
    def wait():
        deadline = time.monotonic() + 5
        while workspace.busy and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(10)
        assert not workspace.busy, workspace.stage
    yield workspace, wait, calls
    workspace.shutdown()


def snapshot(w):
    return deepcopy((w.content, w.navigationItems, w._xref_page, w.evidenceLocation,
                     w._history, w._result.notes))


def test_first_middle_partial_last_and_previous(view):
    w, wait, calls = view
    w.showTab('JEB XREF')
    wait()
    assert w.xrefPageLabel == '1–300 / 603 references'
    assert w.xrefHasNext and not w.xrefHasPrevious
    w.previousXrefPage()
    assert len(calls) == 1
    w.nextXrefPage()
    w.nextXrefPage()  # Busy requests must not enqueue another job.
    wait()
    assert w.xrefPageLabel == '301–600 / 603 references'
    w.nextXrefPage()
    wait()
    assert w.xrefPageLabel == '601–603 / 603 references'
    assert not w.xrefHasNext and w.xrefHasPrevious
    assert len(w.navigationItems) == 1  # Raw duplicates retained, links deduplicated.
    assert len(w._xref_page['items']) == 3
    w.nextXrefPage()
    assert len(calls) == 3
    w.previousXrefPage()
    wait()
    assert w.xrefPageLabel == '301–600 / 603 references'
    assert w.analystNote == 'unchanged'


@pytest.mark.parametrize('failure', ['error', 'cancel', 'malformed', 'late_cancel'])
def test_failed_page_keeps_all_previous_state(view, monkeypatch, failure):
    w, wait, _ = view
    w.showTab('JEB XREF')
    wait()
    before = snapshot(w)
    def query(*args, **kwargs):
        if failure == 'error':
            raise RuntimeError('synthetic failure')
        if failure == 'cancel':
            w.cancel_token.cancel()
            w.cancel_token.check()
        return dict(offset=300, total=603, items=[])
    if failure == 'late_cancel':
        # Run the worker, then cancel after completion but before the GUI commit.
        def start(work, finish):
            w._busy = True
            w._finish_callback = finish
            value = work(None)
            w.cancel_token.cancel()
            w._success(value)
        monkeypatch.setattr(w, '_start', start)
    else:
        monkeypatch.setattr(w.app.backend, 'get_jeb_xrefs', query)
    w.nextXrefPage()
    wait()
    assert snapshot(w) == before
    assert not w._xref_pending


def test_empty_page(view, monkeypatch):
    w, wait, _ = view
    monkeypatch.setattr(w.app.backend, 'get_jeb_xrefs',
                        lambda *a, **kw: dict(offset=0, total=0, items=[]))
    w.showTab('JEB XREF')
    wait()
    assert w.xrefPageLabel == '0–0 / 0 references'
    assert not w.xrefHasNext and not w.xrefHasPrevious and not w.navigationItems


@pytest.mark.parametrize('destination', ['finding', 'location', 'section', 'tab'])
def test_leaving_page_clears_pagination(view, destination):
    w, wait, _ = view
    w.showTab('JEB XREF')
    wait()
    if destination == 'finding':
        w.selectFinding(0)
    elif destination == 'location':
        w.navigateMethod(ENTRY)
    elif destination == 'section':
        w.section('Overview')
    else:
        w.showTab('Evidence')
    assert w._xref_page is None
    assert not w.xrefHasNext and not w.xrefHasPrevious


def test_stale_response_not_committed(view, monkeypatch):
    w, wait, _ = view
    w.showTab('JEB XREF')
    wait()
    before = snapshot(w)
    def start(work, finish):
        w._busy = True
        w._finish_callback = finish
        value = work(None)
        w._selected = deepcopy(w._selected)
        w._success(value)
    monkeypatch.setattr(w, '_start', start)
    w.nextXrefPage()
    assert 'Stale XREF response discarded' in w.stage
    assert snapshot(w) == before
