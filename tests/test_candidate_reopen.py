from copy import deepcopy

import pytest

from analyzer.app.candidate_artifact import compare_origin, save_candidate
from analyzer.core.models import AnalysisResult, Method, Instruction
from test_candidate_artifact import artifact
from test_dex_browser import browser


def matching_result():
    result = AnalysisResult('fixture.apk', 'a' * 64, provenance={'version': 'fixture-version'})
    result.program.methods['Lcaller;->run()V'] = Method('Lcaller;->run()V', unit='u',
        instructions=[Instruction(0, 'invoke-static', target='Ltarget;->run()V')])
    result.program.method_index = [dict(signature='Ltarget;->run()V', unit='u', declared=True, has_code=True)]
    return result


@pytest.mark.parametrize('case', ['match', 'no_project', 'hash', 'unit', 'operand', 'declaration', 'version'])
def test_saved_origin_comparison(case):
    result = matching_result()
    if case == 'hash':
        result.sha256 = 'b' * 64
    if case == 'unit':
        result.program.methods['Lcaller;->run()V'].unit = 'v'
    if case == 'operand':
        result.program.methods['Lcaller;->run()V'].instructions[0].opcode = 'invoke-virtual'
    if case == 'declaration':
        result.program.method_index.clear()
    if case == 'version':
        result.provenance.clear()
    value = compare_origin(artifact(), None if case == 'no_project' else result)
    assert value['status'] == ('NO_PROJECT' if case == 'no_project' else 'SAVED_METADATA_MATCH' if case == 'match' else 'MISMATCH_OR_UNKNOWN')
    assert 'Unsigned' in value['warning']


def test_gui_reopen_failure_and_no_mutation(browser, tmp_path, monkeypatch):
    w, wait = browser
    result = matching_result()
    w._loaded(result)
    before, content = deepcopy(result.to_dict()), w.content
    path = tmp_path / 'saved.candidate.json'
    value = artifact()
    save_candidate(path, value)
    monkeypatch.setattr(w.app.backend, '_run', lambda *a, **kw: pytest.fail('No JEB access'))
    w.reopenCandidate(str(path))
    wait()
    assert 'SAVED_METADATA_MATCH' in w.candidateText
    assert w._candidate_record == value
    text = w.candidateText
    w.reopenCandidate(str(tmp_path / 'absent.candidate.json'))
    wait()
    assert w.candidateText == text and w.content == content
    assert result.to_dict() == before
