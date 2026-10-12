import json
import pytest
from analyzer.app.settings import Settings
from analyzer.app.project_manager import open_project, save_project, write_json
from analyzer.core.models import AnalysisResult, Finding
from analyzer.core.input_validation import read_json


@pytest.mark.parametrize('value', [[], None, {'unknown': 1}, {'timeout_seconds': True},
    {'cache_enabled': 'false'}, {'max_flow_steps': -1}, {'max_methods': 0},
    {'max_call_depth': 129}, {'timeout_seconds': 86401}, {'jeb_path': '   '},
    {'java': 'java\nother'}, {'max_methods': 1.2}])
def test_settings_reject_bad_input_unchanged(tmp_path, value):
    path = tmp_path / 'settings.json'
    path.write_text(json.dumps(value), encoding='utf-8')
    before = path.read_bytes()
    with pytest.raises(ValueError):
        Settings.load(path)
    assert path.read_bytes() == before


def test_settings_defaults_roundtrip_and_invalid_save(tmp_path):
    path = tmp_path / 'settings.json'
    settings = Settings.load(path)
    settings.save(path)
    assert Settings.load(path) == settings
    before = path.read_bytes()
    settings.cache_enabled = 'false'
    with pytest.raises(ValueError):
        settings.save(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize('content', [b'{', b'\xff', b'{"x":1,"x":2}', b'{"x":NaN}',
    b'{"x":Infinity}', b'{"x":1e9999}',
    pytest.param(b'[' * 1100 + b'0' + b']' * 1100, id='excessive-nesting')])
def test_strict_json(tmp_path, content):
    path = tmp_path / 'bad.json'
    path.write_bytes(content)
    with pytest.raises(ValueError):
        read_json(path, 4096)


def test_file_size_limits(tmp_path, monkeypatch):
    import analyzer.app.settings as settings_module
    import analyzer.app.project_manager as project_module
    path = tmp_path / 'oversize.json'
    path.write_bytes(b' ' * 101)
    monkeypatch.setattr(settings_module, 'MAX_SETTINGS_BYTES', 100)
    monkeypatch.setattr(project_module, 'MAX_PROJECT_BYTES', 100)
    for loader in (Settings.load, open_project):
        with pytest.raises(ValueError, match='byte limit'):
            loader(path)


@pytest.mark.parametrize('changes', [
    {'schema_version': True}, {'complete': 'false'}, {'notes': {'f': 3}},
    {'unknown': 3}, {'program': []}, {'findings': {}}, {'diagnostics': [None]},
    {'files': [{'path': 'a', 'size': True}]}, {'provenance': {'flow_coverage': []}},
    {'program': {'methods': {'wrong': {'signature': 'other'}}}},
    {'program': {'methods': {'m': {'signature': 'm', 'instructions': [
        {'offset': True, 'opcode': 'return'}]}}}},
])
def test_project_schema_rejected(tmp_path, changes):
    value = AnalysisResult('app.apk', 'abc').to_dict()
    value.update(changes)
    path = tmp_path / 'bad.json'
    write_json(path, value)
    with pytest.raises(ValueError):
        open_project(path)


@pytest.mark.parametrize('changes', [{'severity': 'UNKNOWN'}, {'location': {'offset': -1}},
    {'data_flow': [{'offset': '0', 'method': 'm', 'label': 'source'}]}, {'evidence': [None]}])
def test_bad_finding_rejected(tmp_path, changes):
    result = AnalysisResult('app.apk', 'abc', findings=[Finding('r', 'title', '', 'WEBVIEW')]).to_dict()
    result['findings'][0].update(changes)
    path = tmp_path / 'bad.json'
    write_json(path, result)
    with pytest.raises(ValueError):
        open_project(path)


def test_nonfinite_save_preserves_file(tmp_path):
    path = tmp_path / 'project.json'
    save_project(path, AnalysisResult('old.apk', 'old', notes={'r': 'keep'}))
    before = path.read_bytes()
    with pytest.raises(ValueError):
        save_project(path, AnalysisResult('new.apk', 'new', provenance={'number': float('nan')}))
    assert path.read_bytes() == before
    assert not list(tmp_path.glob('.aoseye-*'))


def test_project_nested_extension_limit():
    value = AnalysisResult('app.apk', 'abc').to_dict()
    item = value['provenance']
    for _ in range(70):
        item['nested'] = {}
        item = item['nested']
    with pytest.raises(ValueError, match='nesting'):
        AnalysisResult.from_dict(value)


def test_duplicate_finding_ids_rejected():
    finding = Finding('r', 'title', '', 'WEBVIEW')
    value = AnalysisResult('app.apk', 'abc', findings=[finding, finding]).to_dict()
    with pytest.raises(ValueError, match='Duplicate finding'):
        AnalysisResult.from_dict(value)


@pytest.mark.parametrize('offsets', [[0, 0], [-1]])
def test_invalid_instruction_offsets(offsets):
    value = AnalysisResult('app.apk', 'abc').to_dict()
    value['program']['methods'] = {'m': {'signature': 'm', 'instructions': [
        {'offset': offset, 'opcode': 'return'} for offset in offsets]}}
    with pytest.raises(ValueError, match='offsets'):
        AnalysisResult.from_dict(value)


@pytest.mark.parametrize('failure', ['replace', 'size'])
def test_atomic_save_failures_preserve_file(tmp_path, monkeypatch, failure):
    import analyzer.app.project_manager as manager
    path = tmp_path / 'project.json'
    save_project(path, AnalysisResult('old.apk', 'old', notes={'r': 'keep'}))
    before = path.read_bytes()
    if failure == 'replace':
        def fail(*args):
            raise OSError('simulated replace failure')
        monkeypatch.setattr(manager.os, 'replace', fail)
    else:
        monkeypatch.setattr(manager, 'MAX_PROJECT_BYTES', 10)
    with pytest.raises((OSError, ValueError)):
        save_project(path, AnalysisResult('new.apk', 'new'))
    assert path.read_bytes() == before
    assert not list(tmp_path.glob('.aoseye-*'))


def test_settings_oversize_save_preserves_file(tmp_path, monkeypatch):
    import analyzer.app.settings as module
    path = tmp_path / 'settings.json'
    Settings().save(path)
    before = path.read_bytes()
    monkeypatch.setattr(module, 'MAX_SETTINGS_BYTES', 10)
    with pytest.raises(ValueError, match='byte limit'):
        Settings().save(path)
    assert path.read_bytes() == before
