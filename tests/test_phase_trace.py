import importlib.util
import json
from pathlib import Path

from analyzer.app.settings import Settings
from analyzer.backends.jeb.session import JebSession

path = Path(__file__).resolve().parents[1] / 'src/analyzer/backends/jeb/scripts/PhaseTrace.py'
spec = importlib.util.spec_from_file_location('phase_trace', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_bounded_flushed_checkpoints(tmp_path):
    target = tmp_path / 'phases.jsonl'
    trace = module.PhaseTrace(str(target), metrics=lambda: dict(heap_used=10, gc_millis=3))
    for _ in range(300):
        trace.mark('metadata', declarations=7)
    rows = [json.loads(row) for row in target.read_text().splitlines()]
    assert len(rows) == 256 and rows[0]['heap_used'] == 10
    assert rows[0]['declarations'] == 7 and rows[0]['timestamp_epoch_seconds'] > 0


def test_optional_diagnostics_failure(tmp_path):
    trace = module.PhaseTrace(str(tmp_path / 'missing/trace'), metrics=lambda: {})
    trace.mark('test')
    assert trace.count == 0


def test_capture_preserves_complete_rows_before_torn_tail(tmp_path):
    target = tmp_path / 'phases.jsonl'
    target.write_bytes(b'{"phase":"index_done","heap_used":123}\n{"phase":')
    session = JebSession(Settings())
    session._phase_path = target
    session._capture_phases()
    assert session.phase_trace == [dict(phase='index_done', heap_used=123)]
    target.unlink()
    session._dispose()
    assert session.phase_trace == [dict(phase='index_done', heap_used=123)]


def test_capture_row_and_line_limits(tmp_path):
    target = tmp_path / 'phases.jsonl'
    session = JebSession(Settings())
    session._phase_path = target
    target.write_text('{"phase":"p"}\n' * 300)
    session._capture_phases()
    assert len(session.phase_trace) == 258
    target.write_text('x' * 3000)
    session._capture_phases()
    assert session.phase_trace == []
