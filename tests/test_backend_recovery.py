import pytest

from analyzer.app.jobs import Cancelled
from analyzer.app.settings import Settings
from analyzer.backends.jeb.backend import JebBackend
from analyzer.core.models import AnalysisResult, Finding, Location
from conftest import ENTRY, HELPER
from test_dex_browser import browser


@pytest.mark.parametrize('outcome', ['error', 'cancel', 'late-cancel', 'success', 'save-error', 'invalid'])
def test_probe_preserves_loaded_workspace(browser, flow_program, tmp_path, monkeypatch, outcome):
    w, wait = browser
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    finding = Finding('r', 'Keep finding', '', 'WEBVIEW', location=Location(method=HELPER, offset=0))
    result = AnalysisResult('old.apk', 'old', program=flow_program,
                            findings=[finding], notes={finding.id: 'Keep note'})
    w._loaded(result)
    w.selectFinding(0)
    w.findingLocation()
    w.navigateLocation(ENTRY, 20, '')
    w._tab = 'Review'
    w._review_summary = 'Keep review'
    before = (w.content, dict(w.evidenceLocation), list(w._history), list(w.navigationItems),
              w.currentTab, w.reviewSummary)
    original_settings = w.settings

    def probe(self, cancel):
        if outcome == 'error':
            raise OSError('connection failed')
        if outcome == 'cancel':
            raise Cancelled('cancelled')
        if outcome == 'late-cancel':
            cancel.cancel()
        return {'status': 'Connected', 'version': 'mock'}

    monkeypatch.setattr(JebBackend, 'probe', probe)
    if outcome == 'save-error':
        def fail_save(self):
            raise OSError('disk full')
        monkeypatch.setattr(Settings, 'save', fail_save)
    w.probe(' ' if outcome == 'invalid' else str(tmp_path / 'new-jeb'))
    wait()
    assert w._result is result and w._selected is finding
    assert w.analystNote == 'Keep note'
    assert (w.content, w.evidenceLocation, w._history, w.navigationItems,
            w.currentTab, w.reviewSummary) == before
    assert w.app.backend.program is result.program
    assert not w._probe_pending and w._job is None and w._finish_callback is None
    if outcome in ('save-error', 'invalid'):
        assert w.settings is original_settings
        assert not (tmp_path / 'AOSEye/settings.json').exists()
    elif outcome == 'success':
        assert w.backendStatus == 'Connected · mock'
    else:
        assert w.backendStatus == 'Unavailable'
    # A subsequent retry remains usable, including after late cancellation.
    monkeypatch.setattr(JebBackend, 'probe', lambda self, cancel: {'status': 'Connected', 'version': 'retry'})
    w.checkBackend()
    wait()
    assert w.backendStatus == 'Connected · retry'
    assert w.content == before[0] and w.analystNote == 'Keep note'


def test_probe_while_busy_does_not_save_or_replace_settings(browser, tmp_path, monkeypatch):
    w, _ = browser
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    original = w.settings
    w._busy = True
    try:
        w.probe(str(tmp_path / 'ignored'))
        assert w.settings is original and not w._probe_pending
        assert not (tmp_path / 'AOSEye/settings.json').exists()
    finally:
        w._busy = False
