from copy import deepcopy
import json
import pytest
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.project_manager import open_project, save_project
from analyzer.core.input_validation import read_json, validate_project
from analyzer.core.models import AnalysisResult, Program, Finding, Location
from test_dex_browser import browser


class CancelAfter(Cancellation):
    def __init__(self, checks):
        super().__init__()
        self.remaining = checks

    def check(self):
        self.remaining -= 1
        if self.remaining <= 0:
            self.cancel()
        super().check()


def test_cancelled_load_does_not_open_file(tmp_path):
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        open_project(tmp_path / 'missing.json', token)


@pytest.mark.parametrize('phase', ['Validating project schema', 'Building project model'])
def test_cancel_at_load_phase_preserves_disk(tmp_path, flow_program, phase):
    path = tmp_path / 'project.json'
    save_project(path, AnalysisResult('fixture.apk', 'abc', program=flow_program))
    before = path.read_bytes()
    token = Cancellation()
    def progress(percent, name):
        if name == phase:
            token.cancel()
    with pytest.raises(Cancelled):
        open_project(path, token, progress)
    assert path.read_bytes() == before


@pytest.mark.parametrize('payload,checks', [
    (' ' * (2 * 1024 * 1024) + '{}', 3),
    (json.dumps([{'value': n} for n in range(1000)]), 20),
    (json.dumps(list(range(5000))), 8),
], ids=['chunked-read', 'json-objects', 'depth-walk'])
def test_read_chunks_json_objects_and_depth_walk_are_cancellable(tmp_path, payload, checks):
    path = tmp_path / 'input.json'
    path.write_text(payload)
    with pytest.raises(Cancelled):
        read_json(path, 4 * 1024 * 1024, CancelAfter(checks))


def test_schema_walk_and_model_conversion_cancel_without_mutating_public_input(flow_program):
    raw = AnalysisResult('fixture.apk', 'abc', program=flow_program).to_dict()
    before = deepcopy(raw)
    with pytest.raises(Cancelled):
        validate_project(raw, CancelAfter(5))
    with pytest.raises(Cancelled):
        Program.from_dict(raw['program'], cancel=CancelAfter(3))
    assert raw == before


def snapshot(w):
    return deepcopy((w.content, w.detail, w.currentTab, w.evidenceLocation, w._history,
                     w.navigationItems, w._result.notes, w.reviewSummary, w.projectName))


@pytest.mark.parametrize('kind', ['cancel', 'late_cancel', 'error', 'stale'])
def test_reopen_result_commit_is_transactional(browser, monkeypatch, kind):
    w, wait = browser
    method = next(iter(w._result.program.methods))
    finding = Finding('original', 'Keep selected finding', '', 'WEBVIEW',
                      location=Location(method=method, offset=0))
    w._result.findings = [finding]
    w.model.reset([finding])
    w.selectFinding(0)
    w.findingLocation()
    w._result.notes['old'] = 'keep'
    w._tab = 'Review'
    w._review_summary = 'keep summary'
    original = w._result
    before = snapshot(w)
    replacement = AnalysisResult('new.apk', 'new')
    def load(*args):
        if kind == 'cancel':
            raise Cancelled('cancel')
        if kind == 'error':
            raise ValueError('invalid project')
        return replacement
    monkeypatch.setattr('analyzer.gui.controllers.workspace.open_project', load)
    if kind in ('late_cancel', 'stale'):
        def start(work, finish):
            w._busy = True
            w._finish_callback = finish
            value = work(lambda *args: None)
            if kind == 'late_cancel':
                w.cancel_token.cancel()
            else:
                w._result = deepcopy(original)
            w._success(value)
        monkeypatch.setattr(w, '_start', start)
    w.reopen('new.json')
    wait()
    assert snapshot(w) == before
    assert w._selected is finding
    assert w._result is not replacement and not w._reopen_pending
    assert 'cancel' in w.stage.lower() or 'invalid' in w.stage or 'Stale' in w.stage


def test_successful_retry_after_cancel_and_busy_reopen_ignored(browser, monkeypatch):
    w, wait = browser
    original = w._result
    w._busy = True
    w.reopen('ignored.json')
    assert not w._reopen_pending
    w._busy = False
    def load(path, cancel, progress):
        cancel.cancel()
        cancel.check()
    monkeypatch.setattr('analyzer.gui.controllers.workspace.open_project', load)
    w.reopen('cancel.json')
    wait()
    assert w._result is original
    replacement = AnalysisResult('success.apk', 'abc')
    monkeypatch.setattr('analyzer.gui.controllers.workspace.open_project', lambda *args: replacement)
    w.reopen('success.json')
    wait()
    assert w._result is replacement and w.projectName == 'success.apk'
