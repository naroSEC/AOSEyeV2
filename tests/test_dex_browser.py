import os
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import pytest
from PySide6.QtGui import QGuiApplication
from PySide6.QtTest import QTest
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.settings import Settings
from analyzer.core.models import AnalysisResult, Finding, Instruction, Location, Method, Program
from analyzer.gui.controllers.workspace import Workspace
from analyzer.gui.dex_browser import dex_page
from conftest import ENTRY, HELPER


def test_classes_methods_search_and_missing_bodies(flow_program):
    flow_program.classes += ['Lempty;']
    flow_program.methods['Lempty;->abstract()V'] = Method('Lempty;->abstract()V', 'Lempty;')
    flow_program.method_index = [dict(signature='Lexternal;->reference()V', declared=False)]
    page = dex_page(flow_program)
    assert [r['name'] for r in page['items']] == ['Ltest/Main;', 'Ltest/Nav;', 'Lempty;']
    assert dex_page(flow_program, query='OPEN')['items'][0]['name'] == 'Ltest/Nav;'
    methods = dex_page(flow_program, 'Ltest/Nav;', 'OPEN')
    assert methods['items'] == [dict(name=HELPER, kind='method', has_body=True, unit='', duplicate=False)]
    assert not dex_page(flow_program, 'Lempty;')['items'][0]['has_body']
    assert dex_page(flow_program, query='absent')['total'] == 0


def test_large_inventory_is_bounded_and_cancellable():
    program = Program(methods={f'Llarge;->m{i}()V': Method(f'Llarge;->m{i}()V', 'Llarge;')
                               for i in range(80000)})
    first = dex_page(program, 'Llarge;')
    last = dex_page(program, 'Llarge;', offset=79800)
    assert first['total'] == last['total'] == 80000
    assert len(first['items']) == 300 and first['has_more']
    assert len(last['items']) == 200 and not last['has_more']
    assert last['items'][0]['name'] == 'Llarge;->m79800()V'
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        dex_page(program, cancel=token)


@pytest.fixture
def browser(flow_program):
    app = QGuiApplication.instance() or QGuiApplication([])
    workspace = Workspace(Settings())
    workspace._loaded(AnalysisResult('fixture.apk', '0' * 64, program=flow_program))
    def wait():
        deadline = time.monotonic() + 5
        while workspace.busy and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(10)
        assert not workspace.busy, workspace.stage
    yield workspace, wait
    workspace.shutdown()


def test_browse_without_findings_and_history(browser, monkeypatch):
    w, wait = browser
    w.section('DEX')
    wait()
    assert len(w.dexItems) == 2 and w.sectionName == 'DEX'
    w.openDexClass('Ltest/Nav;')
    wait()
    w.openDexMethod(w.dexItems[0]['name'])
    assert w.evidenceLocation['method'] == HELPER and w.currentTab == 'Bytecode'
    assert not w.detail and w.findingCount == 0
    w.openDexMethod(ENTRY)
    w.goBack()
    assert w.evidenceLocation['method'] == HELPER
    w.showTab('XREF')
    wait()
    assert w.navigationItems[0]['method'] == ENTRY
    for tab in ('Code', 'Bytecode', 'CFG', 'Evidence', 'Data Flow', 'Review'):
        w.showTab(tab)
    assert 'Select a Finding' in w.content
    monkeypatch.setattr(w, '_prepare_live_backend', lambda: None)
    monkeypatch.setattr(w.app.backend, 'get_ast', lambda *a: dict(nodes=['test']))
    monkeypatch.setattr(w.app.backend, 'get_jeb_xrefs', lambda *a, **kw: dict(items=[], total=0, offset=0))
    monkeypatch.setattr(w.app.backend, 'get_decompiled_source', lambda *a: 'supporting source')
    w.showTab('AST')
    wait()
    assert 'nodes' in w.content
    w.showTab('JEB XREF')
    wait()
    assert w.xrefPageLabel == '0–0 / 0 references'
    w.decompile()
    wait()
    assert w.content == 'supporting source'


def test_independent_browse_does_not_relabel_finding_or_change_notes(browser):
    w, wait = browser
    finding = Finding('r', 'Original', '', 'WEBVIEW', location=Location(method=ENTRY, offset=0))
    w._result.findings = [finding]
    w._result.notes[finding.id] = 'keep'
    w.model.reset([finding])
    w.selectFinding(0)
    w.openDexMethod(HELPER)
    assert w._selected is None and w.detail == {} and w.analystNote == ''
    w.note('must not be saved')
    assert w._result.notes == {finding.id: 'keep'}
    w.selectFinding(0)
    assert w.analystNote == 'keep'


def test_browser_page_changes_reset_and_failed_query_preserves_page(browser, monkeypatch):
    w, wait = browser
    for i in range(602):
        signature = f'Lmany;->m{i}()V'
        w._result.program.methods[signature] = Method(signature, 'Lmany;')
    w.openDexClass('Lmany;')
    wait()
    assert w.dexPageLabel == '1–300 / 602'
    w.nextDexPage()
    wait()
    assert w.dexPageLabel == '301–600 / 602'
    w.nextDexPage()
    wait()
    assert w.dexPageLabel == '601–602 / 602' and not w.dexHasNext
    w.previousDexPage()
    wait()
    before = w._dex_page
    def cancelled(*args, **kwargs):
        raise Cancelled('cancel')
    monkeypatch.setattr('analyzer.gui.controllers.workspace.dex_page', cancelled)
    w.searchDex('new query')
    wait()
    assert w._dex_page is before
    w._loaded(AnalysisResult('empty.apk', '0' * 64))
    assert w.dexItems == [] and not w.dexHasNext


def test_no_body_navigation_preserves_location(browser):
    w, wait = browser
    w.openDexMethod(HELPER)
    before = dict(w.evidenceLocation)
    w._result.program.methods['Lempty;->m()V'] = Method('Lempty;->m()V')
    w.openDexMethod('Lempty;->m()V')
    assert w.evidenceLocation == before and 'No indexed DEX body' in w.stage
