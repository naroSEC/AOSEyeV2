import os
from pathlib import Path

import pytest

from analyzer.app.settings import Settings
from analyzer.app.jobs import Cancellation


@pytest.mark.parametrize('key,value', [('max_index_entries', 0), ('max_index_entries', 200001),
    ('max_index_entries', True), ('max_index_entries', '10'), ('max_index_mib', 0),
    ('max_index_mib', 65), ('max_index_mib', 1.0)])
def test_invalid_limits(key, value):
    with pytest.raises(ValueError):
        Settings(**{key: value})


def test_old_settings_and_roundtrip(tmp_path):
    target = tmp_path / 'settings.json'
    target.write_text('{}')
    settings = Settings.load(target)
    assert (settings.max_index_entries, settings.max_index_mib) == (20000, 8)
    settings.max_index_entries, settings.max_index_mib = 1000, 1
    settings.save(target)
    assert Settings.load(target) == settings


@pytest.mark.parametrize('setting', ['max_index_entries', 'max_index_mib'])
def test_index_budget_cache_isolation(tmp_path, monkeypatch, setting):
    from analyzer.backends.jeb.backend import JebBackend
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    apk = tmp_path / 'input.apk'
    apk.write_bytes(b'test')
    calls = []
    with JebBackend(Settings()) as backend:
        monkeypatch.setattr(backend, 'probe', lambda *args: {})
        def run(operation, token, receive, **kwargs):
            calls.append((kwargs['max_index_entries'], kwargs['max_index_bytes']))
            records = tmp_path / 'records'
            records.write_bytes(b'')
            return receive({'program': {}}, records)
        monkeypatch.setattr(backend, '_run', run)
        backend.load(apk, Cancellation())
        backend.load(apk, Cancellation())
        setattr(backend.settings, setting, 1)
        backend.load(apk, Cancellation())
        assert len(calls) == 2 and calls[0] != calls[1]


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
@pytest.mark.parametrize('mode', ['count', 'bytes'])
def test_live_declaration_limits(mode):
    from analyzer.backends.jeb.backend import JebBackend, file_hash
    fixture = Path(__file__).resolve().parents[1] / 'build/fixtures/flow-fixture.apk'
    with JebBackend(Settings(jvm_heap_mib=1024, cache_enabled=False)) as backend:
        backend.input_path, backend.input_sha256 = fixture, file_hash(fixture)
        def receive(response, records):
            response['body_bytes'] = records.stat().st_size
            return response
        value = backend._run('index', Cancellation(), receive=receive, **backend._input_request(),
            max_index_entries=1 if mode == 'count' else 20000,
            max_index_bytes=1 if mode == 'bytes' else 1024 * 1024)
        program = value['program']
        maximum = 1 if mode == 'count' else 0
        for field in ('class_index', 'field_index', 'method_index'):
            assert len(program[field]) <= maximum
        assert len(program['classes']) == len(program['class_index'])
        assert len(program['fields']) == len(program['field_index'])
        assert any('Declaration index budget exhausted' in d for d in program['diagnostics'])
        phases = [r['phase'] for r in backend.session.phase_trace]
        assert 'declaration_index_limit' in phases and 'response_serialization_done' in phases


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_live_application_partial_save(tmp_path):
    from analyzer.app.application import AnalysisApplication
    from analyzer.app.project_manager import save_project, open_project
    fixture = Path(__file__).resolve().parents[1] / 'build/fixtures/flow-fixture.apk'
    application = AnalysisApplication(Settings(max_index_entries=1, cache_enabled=False, jvm_heap_mib=1024))
    try:
        result = application.analyze(fixture, Cancellation())
        assert not result.complete
        assert any('Declaration index budget exhausted' in d for d in result.diagnostics)
        path = tmp_path / 'partial.json'
        save_project(path, result)
        loaded = open_project(path)
        assert not loaded.complete and loaded.diagnostics == result.diagnostics
        assert loaded.provenance['index_entries_per_kind'] == 1
        assert loaded.provenance['call_target_coverage'] == result.provenance['call_target_coverage']
        assert loaded.provenance['call_target_coverage']['scope'] == 'saved_exact_operands'
    finally:
        application.backend.close()
