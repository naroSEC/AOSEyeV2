import gc
import logging
import weakref
import json
from pathlib import Path
import subprocess
import sys
import pytest
from analyzer.app.project_manager import save_project
from analyzer.app.jobs import Cancelled
from analyzer.core.models import AnalysisResult, Program
from test_dex_browser import browser


def test_reopen_releases_old_result_and_backend_program(browser, tmp_path):
    w, wait = browser
    w._loaded(AnalysisResult('old.apk', 'old', program=Program()))
    old_result = weakref.ref(w._result)
    old_program = weakref.ref(w._result.program)
    # Local tabs also bind the backend to the current normalized program.
    w.app.backend.program = w._result.program
    path = tmp_path / 'new.json'
    save_project(path, AnalysisResult('new.apk', 'abc'))
    w.reopen(str(path))
    wait()
    w.pool.waitForDone()
    gc.collect()
    assert old_result() is None
    assert old_program() is None
    assert w.app.backend.program is w._result.program
    assert w._finish_callback is None and w._job is None


@pytest.mark.parametrize('outcome', ['success', 'failure', 'cancel'])
def test_job_closures_release_captured_models(browser, outcome, monkeypatch):
    w, wait = browser
    # pytest's reporting handler retains traceback frames, unlike a file logger.
    monkeypatch.setattr(logging.getLogger('analyzer.gui.controllers.workspace'), 'exception', lambda *args: None)
    transient = Program()
    reference = weakref.ref(transient)
    def work(_, captured=transient):
        if outcome == 'failure':
            raise ValueError('synthetic failure')
        if outcome == 'cancel':
            raise Cancelled('synthetic cancel')
        return len(captured.methods)
    def finish(value, captured=transient):
        assert not captured.methods
    w._start(work, finish)
    del transient, work, finish
    wait()
    w.pool.waitForDone()
    gc.collect()
    assert reference() is None
    assert w._finish_callback is None and w._job is None


def test_finish_can_start_next_job_without_cleanup_clobber(browser):
    w, wait = browser
    completed = []
    def first(value):
        completed.append(value)
        w._start(lambda _: 'second', completed.append)
    w._start(lambda _: 'first', first)
    wait()
    assert completed == ['first', 'second']
    assert w._finish_callback is None and w._job is None


def test_repeated_reopen_tool_preserves_inputs(tmp_path):
    source, output = tmp_path / 'input.json', tmp_path / 'metrics.json'
    save_project(source, AnalysisResult('fixture.apk', 'abc'))
    before = source.read_bytes()
    tool = Path(__file__).resolve().parents[1] / 'tools/validate_reopen_stability.py'
    run = subprocess.run([sys.executable, str(tool), str(source), '--cycles', '2', '-o', str(output)],
                         capture_output=True, timeout=30)
    assert run.returncode == 0, run.stderr.decode(errors='replace')
    report = json.loads(output.read_text())
    assert len(report['rounds']) == 2
    assert all(row['retired_objects_alive'] == 0 for row in report['rounds'])
    assert source.read_bytes() == before
