from copy import deepcopy
import pytest
from analyzer.app.project_manager import open_project, save_project
from analyzer.core.models import AnalysisResult


def test_default_conversion_preserves_input_and_owned_conversion_order(flow_program):
    raw = AnalysisResult('fixture.apk', 'abc', program=flow_program, notes={'keep': 'note'}).to_dict()
    before = deepcopy(raw)
    expected = AnalysisResult.from_dict(raw)
    assert raw == before
    result = AnalysisResult.from_dict(raw, consume=True)
    assert result == expected
    assert list(result.program.methods) == list(expected.program.methods)
    assert raw['program']['methods'] == {}
    assert result.notes == {'keep': 'note'}


def test_owned_conversion_validates_before_consuming(flow_program):
    raw = AnalysisResult('fixture.apk', 'abc', program=flow_program).to_dict()
    raw['notes'] = {'invalid': 5}
    before = deepcopy(raw)
    with pytest.raises(ValueError):
        AnalysisResult.from_dict(raw, consume=True)
    assert raw == before


def test_optimized_reopen_is_read_only_and_exact(flow_program, tmp_path):
    source = tmp_path / 'project.json'
    expected = AnalysisResult('fixture.apk', 'abc', program=flow_program,
                              notes={'unicode': '\ud800😀'}, provenance={'value': [1, None, True]})
    save_project(source, expected)
    before = source.read_bytes()
    assert open_project(source) == expected
    assert source.read_bytes() == before
