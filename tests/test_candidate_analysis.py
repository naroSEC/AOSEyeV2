from copy import deepcopy
from types import SimpleNamespace as NS

import pytest

from analyzer.app.candidate_analysis import expand_candidate
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.settings import Settings
from analyzer.backends.jeb.backend import file_hash
from test_candidate_artifact import artifact
from test_candidate_reopen import matching_result


@pytest.mark.parametrize('case', ['success', 'live_mismatch', 'cancel', 'count_budget', 'byte_budget', 'origin'])
def test_expansion_preserves_original_and_backend(tmp_path, monkeypatch, case):
    import analyzer.app.candidate_analysis as module
    original = matching_result()
    path = tmp_path / 'fixture.dex'
    path.write_bytes(b'fixture')
    original.input_path, original.sha256 = str(path), file_hash(path)
    value = artifact()
    value['candidate']['input_sha256'] = original.sha256
    if case == 'count_budget':
        original.provenance['candidate_expansions'] = [{}] * 8
    if case == 'byte_budget':
        original.provenance['candidate_expansions'] = [dict(encoded_bytes=2 * 1024 * 1024)]
    if case == 'origin':
        original.sha256 = 'b' * 64
    before = deepcopy(original.to_dict())
    prior_program = object()
    backend = NS(program=prior_program, input_path=None, input_sha256='', version='fixture-version')
    token = Cancellation()
    def preview(*args, **kwargs):
        candidate = deepcopy(value['candidate'])
        if case == 'live_mismatch':
            candidate['method']['source'] = 'modified'
        if case == 'cancel':
            token.cancel()
        return candidate
    backend.preview_call_target = preview
    class App:
        def __init__(self, settings, delegate):
            self.delegate = delegate
        def analyze(self, path, cancel, progress):
            result = deepcopy(original)
            result.program = self.delegate.load(path, cancel)
            return result
    monkeypatch.setattr(module, 'AnalysisApplication', App)
    if case == 'success':
        result = expand_candidate(original, value, backend, Settings(), token)
        assert 'Ltarget;->run()V' in result.program.methods
        assert len(result.provenance['candidate_expansions']) == 1 and not result.complete
    else:
        with pytest.raises((ValueError, Cancelled)):
            expand_candidate(original, value, backend, Settings(), token)
    assert original.to_dict() == before
    assert backend.program is prior_program and backend.input_path is None and backend.input_sha256 == ''
