from copy import deepcopy
from hashlib import sha256

import pytest

from analyzer.app.project_manager import open_project, save_project
from analyzer.core.models import AnalysisResult, Finding, Location
from conftest import ENTRY, HELPER
from test_dex_browser import browser


@pytest.mark.parametrize('operation', ['AST', 'JEB XREF', 'Code'])
@pytest.mark.parametrize('failure', ['missing', 'changed', 'late-cancel'])
def test_live_failure_preserves_saved_evidence_and_retry(browser, flow_program, tmp_path,
                                                        monkeypatch, operation, failure):
    w, wait = browser
    original = tmp_path / 'original.dex'
    original.write_bytes(b'original fixture bytes')
    finding = Finding('r', 'Saved evidence', '', 'WEBVIEW', location=Location(method=HELPER, offset=0))
    result = AnalysisResult(str(original), sha256(original.read_bytes()).hexdigest(),
                            program=flow_program, findings=[finding], notes={finding.id: 'keep note'})
    w._loaded(result)
    w.selectFinding(0)
    w.findingLocation()
    w.navigateLocation(ENTRY, 20, '')
    w._navigation_items = [{'label': 'saved reference'}]
    before = deepcopy((w.currentTab, w.content, w.navigationItems, w.evidenceLocation, w._history))
    calls = []
    def reply(method, cancel, **kwargs):
        # Preserve the public backend validation contract in this response double.
        w.app.backend._input_request(cancel)
        calls.append(method)
        if failure == 'late-cancel' and len(calls) == 1:
            cancel.cancel()
        if operation == 'AST':
            return {'nodes': [], 'origin': 'synthetic retry'}
        if operation == 'JEB XREF':
            return dict(offset=0, total=0, items=[], evidence_origin='synthetic retry')
        return 'synthetic decompiled source'
    for name in ('get_ast', 'get_jeb_xrefs', 'get_decompiled_source'):
        monkeypatch.setattr(w.app.backend, name, reply)
    if failure == 'missing':
        original.unlink()  # Only this test-created file is removed.
    elif failure == 'changed':
        original.write_bytes(b'changed fixture bytes')
    def request():
        w.decompile() if operation == 'Code' else w.showTab(operation)
        wait()
    request()
    assert (w.currentTab, w.content, w.navigationItems, w.evidenceLocation, w._history) == before
    assert w._result is result and w._selected is finding and w.analystNote == 'keep note'
    assert w._live_snapshot is None and w._job is None and w._finish_callback is None
    if failure != 'late-cancel':
        assert not calls
        assert 'missing or changed' in w.stage
    else:
        assert 'cancelled' in w.stage.lower()
    # Offline evidence remains navigable and serializable, without touching a backend.
    w.showTab('Bytecode')
    assert w.content == before[1]
    project = tmp_path / 'saved.json'
    save_project(project, result)
    reopened = open_project(project)
    assert reopened.notes == result.notes and reopened.program.methods.keys() == flow_program.methods.keys()
    original.write_bytes(b'original fixture bytes')
    request()
    assert len(calls) == (2 if failure == 'late-cancel' else 1)
    assert w.currentTab == operation and w._live_snapshot is None
    assert w.analystNote == 'keep note'
