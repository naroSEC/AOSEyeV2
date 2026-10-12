import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import time

import pytest
from analyzer.app.jobs import Cancelled

spec = importlib.util.spec_from_file_location('validate_apks', Path(__file__).resolve().parents[1] / 'tools/validate_apks.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@pytest.mark.parametrize('case', ['failure', 'cancel', 'deadline', 'rss', 'available'])
def test_failure_and_guard_report(tmp_path, monkeypatch, case):
    closed = []
    class Application:
        def __init__(self, settings):
            self.settings = settings
            self.backend = SimpleNamespace(session=SimpleNamespace(pid=None), close=lambda: closed.append(True))
        def analyze(self, path, token, progress):
            progress(30, 'synthetic indexing')
            if case == 'failure':
                raise ValueError('synthetic failure')
            if case == 'cancel':
                raise Cancelled('synthetic cancellation')
            for _ in range(30):
                time.sleep(0.05)
                token.check()
            pytest.fail('Guard did not request cancellation')
    monkeypatch.setattr(runner, 'AnalysisApplication', Application)
    monkeypatch.setattr(runner.psutil, 'Process', lambda: SimpleNamespace(memory_info=lambda: SimpleNamespace(rss=10)))
    monkeypatch.setattr(runner.psutil, 'virtual_memory', lambda: SimpleNamespace(available=1000000000))
    output = tmp_path / 'report'
    value = runner.validate(tmp_path / 'input.apk', output, False,
        max_seconds=0.01 if case == 'deadline' else 10,
        max_rss_mib=0.000001 if case == 'rss' else 100,
        min_available_mib=2000 if case == 'available' else 0)
    assert closed and value['bridge_closed']
    assert value['validation_status'] == ('FAILED' if case == 'failure' else 'CANCELLED')
    assert value['complete'] is False and value['stages'][0]['percent'] == 30
    if case not in ('failure', 'cancel'):
        assert value['guard']['reason']
        assert value['guard']['observed_available_bytes'] == 1000000000
        assert value['telemetry'][0]['system_available_bytes'] == 1000000000
        assert value['telemetry'][0]['method_stream_present'] is False
    assert json.loads((output / 'summary.json').read_text()) == value


def test_existing_output_is_not_overwritten(tmp_path):
    with pytest.raises(FileExistsError):
        runner.validate(tmp_path / 'input.apk', tmp_path, False)


@pytest.mark.parametrize('failure', [True, False])
def test_evidence_failure_is_not_reported_as_finished(tmp_path, monkeypatch, failure):
    from zipfile import ZipFile
    from analyzer.core.models import AnalysisResult, Method, Program
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w') as archive:
        archive.writestr('classes.dex', b'fixture')
    signature = 'Ltest/A;->run()V'
    class Application:
        def __init__(self, settings):
            self.settings = settings
            def source(*args):
                if failure:
                    raise ValueError('synthetic evidence failure')
                return 'void run() {}'
            self.backend = SimpleNamespace(session=SimpleNamespace(pid=None), close=lambda: None,
                session_info={}, capabilities={}, get_decompiled_source=source,
                get_ast=lambda *args: dict(nodes=[], truncated=False),
                get_jeb_xrefs=lambda *args: dict(total=0), get_cfg=lambda *args: [])
        def analyze(self, path, token, progress):
            return AnalysisResult(str(path), '0' * 64, complete=True,
                program=Program(methods={signature: Method(signature, 'Ltest/A;')}))
    monkeypatch.setattr(runner, 'AnalysisApplication', Application)
    result = runner.validate(apk, tmp_path / 'out', False)
    assert result['validation_status'] == ('EVIDENCE_FAILED' if failure else 'FINISHED')
    assert result['complete'] is True  # Analysis completion and evidence QA are distinct.


@pytest.mark.parametrize('kwargs', [dict(max_seconds=0), dict(max_rss_mib=0), dict(min_available_mib=-1)])
def test_invalid_limits(tmp_path, kwargs):
    with pytest.raises(ValueError):
        runner.validate(tmp_path / 'input.apk', tmp_path / 'out', False, **kwargs)
    assert not (tmp_path / 'out').exists()


@pytest.mark.parametrize('cpu_available', [True, False])
def test_progress_stream_and_optional_cpu(tmp_path, monkeypatch, cpu_available):
    stream = tmp_path / 'one.methods.jsonl'
    stream.write_bytes(b'x' * 128)
    class Application:
        def __init__(self, settings):
            self.settings = settings
            self.backend = SimpleNamespace(session=SimpleNamespace(pid=123, _directory=SimpleNamespace(name=str(tmp_path))))
            self.backend.close = lambda: setattr(self.backend.session, 'pid', None)
        def analyze(self, path, token, progress):
            for _ in range(30):
                time.sleep(0.05)
                token.check()
            pytest.fail('Guard did not cancel')
    def cpu():
        if not cpu_available:
            raise runner.psutil.AccessDenied(123)
        return SimpleNamespace(user=2.0, system=3.0)
    monkeypatch.setattr(runner, 'AnalysisApplication', Application)
    monkeypatch.setattr(runner.psutil, 'Process', lambda *args: SimpleNamespace(
        memory_info=lambda: SimpleNamespace(rss=10), children=lambda **kw: [], cpu_times=cpu))
    monkeypatch.setattr(runner.psutil, 'virtual_memory', lambda: SimpleNamespace(available=1000000000))
    result = runner.validate(tmp_path / 'input.apk', tmp_path / 'out', False, max_seconds=0.01)
    row = result['telemetry'][0]
    assert row['method_stream_bytes'] == 128 and row['method_stream_present']
    assert row['java_cpu_seconds'] == (5.0 if cpu_available else None)
    assert result['guard']['observed_combined_rss'] == 20
    assert result['bridge_closed']
