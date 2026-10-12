import importlib.util
import json
import os
from pathlib import Path

import pytest

from analyzer.app.settings import Settings
from analyzer.app.jobs import Cancellation

path = Path(__file__).resolve().parents[1] / 'src/analyzer/backends/jeb/scripts/ExportBudget.py'
spec = importlib.util.spec_from_file_location('export_budget', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_exact_ascii_jsonl_boundary():
    data = {'text': '한글😀'}
    encoded = (json.dumps(data, ensure_ascii=True) + '\n').encode('ascii')
    budget = module.ExportBudget(len(encoded))
    assert budget.record(data).encode('ascii') == encoded
    assert budget.used == len(encoded) and not budget.exhausted
    assert budget.record({}) is None
    assert budget.exhausted and budget.skipped == 1
    assert budget.record({}) is None and budget.skipped == 2


def test_first_large_record_does_not_write_partial_line():
    budget = module.ExportBudget(1)
    assert budget.record({'large': 'x' * 100}) is None
    assert budget.used == 0 and budget.skipped == 1


@pytest.mark.parametrize('value', [0, -1, True, '64', 1.0, 257])
def test_invalid_settings(value):
    with pytest.raises(ValueError):
        Settings(max_export_mib=value)


def test_legacy_settings_and_roundtrip(tmp_path):
    target = tmp_path / 'settings.json'
    target.write_text('{}')
    assert Settings.load(target).max_export_mib == 64
    Settings(max_export_mib=8).save(target)
    assert Settings.load(target).max_export_mib == 8


def test_budget_changes_cache_key(tmp_path, monkeypatch):
    from analyzer.backends.jeb.backend import JebBackend
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    apk = tmp_path / 'input.apk'
    apk.write_bytes(b'test')
    calls = []
    with JebBackend(Settings(max_export_mib=1)) as backend:
        monkeypatch.setattr(backend, 'probe', lambda *args: {})
        def run(operation, token, receive, **kwargs):
            calls.append(kwargs['max_export_bytes'])
            records = tmp_path / 'records.jsonl'
            records.write_bytes(b'')
            return receive({'program': {}}, records)
        monkeypatch.setattr(backend, '_run', run)
        backend.load(apk, Cancellation())
        backend.load(apk, Cancellation())
        backend.settings.max_export_mib = 2
        backend.load(apk, Cancellation())
        assert calls == [1024 * 1024, 2 * 1024 * 1024]


def test_oversized_response_rejected_without_replacing_program(tmp_path, monkeypatch):
    from analyzer.backends.jeb.backend import JebBackend
    from analyzer.backends.base import BackendError
    apk = tmp_path / 'input.apk'
    apk.write_bytes(b'test')
    with JebBackend(Settings(max_export_mib=1, cache_enabled=False)) as backend:
        original = backend.program
        monkeypatch.setattr(backend, 'probe', lambda *args: {})
        def run(operation, token, receive, **kwargs):
            records = tmp_path / 'records.jsonl'
            records.write_bytes(b'x' * (1024 * 1024 + 1))
            return receive({'program': {}}, records)
        monkeypatch.setattr(backend, '_run', run)
        with pytest.raises(BackendError, match='byte budget'):
            backend.load(apk, Cancellation())
        assert backend.program is original


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
@pytest.mark.parametrize('limit', [1, 8192])
def test_live_budget_keeps_valid_records_and_declarations(limit):
    from analyzer.backends.jeb.backend import JebBackend, file_hash
    from analyzer.core.models import Program
    from analyzer.app.project_manager import save_project, open_project
    from analyzer.core.models import AnalysisResult
    import tempfile
    fixture = Path(__file__).resolve().parents[1] / 'build/fixtures/flow-fixture.apk'
    with JebBackend(Settings(jvm_heap_mib=1024, cache_enabled=False)) as backend:
        backend.input_path, backend.input_sha256 = fixture, file_hash(fixture)
        def receive(response, records):
            assert records.stat().st_size <= limit
            data = records.read_text(encoding='utf-8')
            rows = [json.loads(line) for line in data.splitlines()]
            if data:
                assert data.endswith('\n')
            response['rows'] = rows
            return response
        value = backend._run('index', Cancellation(), receive=receive,
            **backend._input_request(), max_methods=100000, max_export_bytes=limit)
        program = Program.from_dict(value['program'])
        phases = [r['phase'] for r in backend.session.phase_trace]
        assert 'class_field_metadata_done' in phases and 'index_done' in phases
        assert 'response_serialization_start' in phases
        assert len(program.method_index) > len(value['rows'])
        assert any('byte budget exhausted' in d for d in program.diagnostics)
        assert bool(value['rows']) is (limit > 1)
        for row in value['rows']:
            program.methods.update(Program.from_dict({'methods': {row['signature']: row}}).methods)
        result = AnalysisResult(str(fixture), backend.input_sha256, program=program,
                                diagnostics=program.diagnostics, complete=False)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'partial.json'
            save_project(output, result)
            loaded = open_project(output)
            assert not loaded.complete and len(loaded.program.methods) == len(value['rows'])
            assert loaded.diagnostics == program.diagnostics
