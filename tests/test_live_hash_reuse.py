from hashlib import sha256

import pytest

from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.settings import Settings
from analyzer.backends.base import BackendError
from analyzer.backends.jeb import backend as module
from analyzer.core.models import AnalysisResult, Finding, Location
from conftest import ENTRY
from test_dex_browser import browser


def setup_backend(backend, program, tmp_path, monkeypatch):
    path = tmp_path / 'input.dex'
    path.write_bytes(b'original')
    backend.program = program
    backend.input_path = path
    backend.input_sha256 = sha256(b'original').hexdigest()
    reads, requests = [], []
    original_hash = module.file_hash
    def counted(path, cancel=None):
        reads.append(path)
        return original_hash(path, cancel)
    def response(operation, cancel, **kwargs):
        requests.append(operation)
        return dict(ast={'nodes': ['synthetic']}, source='synthetic source', xrefs=[], total=0)
    monkeypatch.setattr(module, 'file_hash', counted)
    monkeypatch.setattr(backend, '_run', response)
    return path, reads, requests


def invoke(backend, operation, token=None):
    token = token or Cancellation()
    return {'AST': backend.get_ast, 'Code': backend.get_decompiled_source,
            'JEB XREF': backend.get_jeb_xrefs}[operation](ENTRY, token)


@pytest.mark.parametrize('operation', ['AST', 'Code', 'JEB XREF'])
def test_direct_call_hashes_once_each_time_including_cached_returns(flow_program, tmp_path, monkeypatch, operation):
    backend = module.JebBackend(Settings(jeb_path=str(tmp_path)))
    _, reads, requests = setup_backend(backend, flow_program, tmp_path, monkeypatch)
    invoke(backend, operation)
    assert len(reads) == 1
    invoke(backend, operation)
    assert len(reads) == 2
    assert len(requests) == (2 if operation == 'JEB XREF' else 1)


@pytest.mark.parametrize('operation', ['AST', 'Code'])
@pytest.mark.parametrize('failure', ['missing', 'changed', 'cancelled'])
def test_cached_return_still_checks_original_and_cancellation(flow_program, tmp_path, monkeypatch, operation, failure):
    backend = module.JebBackend(Settings(jeb_path=str(tmp_path)))
    path, _, requests = setup_backend(backend, flow_program, tmp_path, monkeypatch)
    cached = invoke(backend, operation)
    token = Cancellation()
    if failure == 'missing':
        path.unlink()  # Only the test-created file.
    elif failure == 'changed':
        path.write_bytes(b'modified')
    else:
        token.cancel()
    with pytest.raises(Cancelled if failure == 'cancelled' else BackendError):
        invoke(backend, operation, token)
    assert len(requests) == 1
    path.write_bytes(b'original')
    assert invoke(backend, operation) == cached
    assert len(requests) == 1


@pytest.mark.parametrize('operation', ['AST', 'Code', 'JEB XREF'])
def test_gui_live_request_reads_once_and_next_request_rechecks(browser, flow_program, tmp_path, monkeypatch, operation):
    w, wait = browser
    path, reads, _ = setup_backend(w.app.backend, flow_program, tmp_path, monkeypatch)
    finding = Finding('r', 'test', '', 'WEBVIEW', location=Location(method=ENTRY, offset=0))
    w._loaded(AnalysisResult(str(path), sha256(b'original').hexdigest(), program=flow_program, findings=[finding]))
    w.selectFinding(0)
    for count in (1, 2):
        w.decompile() if operation == 'Code' else w.showTab(operation)
        wait()
        assert len(reads) == count
        assert 'loaded' in w.stage.lower(), w.stage
