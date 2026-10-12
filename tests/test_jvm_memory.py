import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import os

import pytest

from analyzer.app.settings import Settings
from analyzer.app.jobs import Cancellation
from analyzer.backends.base import BackendError
from analyzer.backends.jeb.session import JebSession
from test_dex_browser import browser


@pytest.mark.parametrize('value', [511, 16385, True, '2048', 2048.0])
def test_invalid_heap(value):
    with pytest.raises(ValueError):
        Settings(jvm_heap_mib=value)


def test_default_and_roundtrip(tmp_path):
    path = tmp_path / 'settings.json'
    path.write_text('{}')
    assert Settings.load(path).jvm_heap_mib == 4096
    Settings(jvm_heap_mib=2048).save(path)
    assert Settings.load(path).jvm_heap_mib == 2048


@pytest.mark.parametrize('message, kind', [('java.lang.OutOfMemoryError: Java heap space', 'JVM_OUT_OF_MEMORY_REPORTED'),
    ('Could not reserve enough space for object heap', 'JVM_STARTUP_MEMORY_OR_CONFIGURATION_FAILURE'),
    ('killed', 'JVM_EXIT_OR_OPERATION_FAILURE_UNCLASSIFIED')])
def test_failure_classification(message, kind):
    session = JebSession(Settings(jvm_heap_mib=2048))
    text = session._failure_message('x' * 9000 + message, -9)
    assert kind in text and 'heap_limit_mib=2048' in text and 'exit_code=-9' in text
    assert len(text) < 6500


class Process:
    def __init__(self):
        self.stdin, self.returncode, self.pid = io.StringIO(), None, 123
    def poll(self):
        return self.returncode
    def terminate(self):
        self.returncode = 0
    kill = terminate
    def wait(self, **kwargs):
        return self.returncode


def test_heap_command_and_lazy_restart(tmp_path, monkeypatch):
    jar = tmp_path / 'bin/app/jeb.jar'
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b'not executed')
    commands, processes = [], []
    def start(command, **kwargs):
        commands.append(command)
        process = Process()
        processes.append(process)
        return process
    monkeypatch.setattr('analyzer.backends.jeb.session.subprocess.Popen', start)
    session = JebSession(Settings(jeb_path=str(tmp_path), jvm_heap_mib=2048))
    try:
        session._start()
        session._start()
        assert len(commands) == 1 and '-Xmx2048m' in commands[0]
        session.heap_mib = 1024
        session._start()
        assert len(commands) == 2 and '-Xmx1024m' in commands[1]
        assert processes[0].stdin.closed
    finally:
        session._dispose()


@pytest.mark.parametrize('oom', [True, False])
def test_response_failure_cleanup(monkeypatch, oom):
    session = JebSession(Settings(jvm_heap_mib=1024))
    session._directory = tempfile.TemporaryDirectory()
    session.process = Process()
    def write(request, payload):
        request.write_text('{}')
        Path(payload['output']).write_text(json.dumps(dict(schema_version=1, request_id=payload['request_id'],
            ok=False, error='java.lang.OutOfMemoryError: heap' if oom else 'ordinary method error')))
    monkeypatch.setattr('analyzer.backends.jeb.session.write_json', write)
    try:
        with pytest.raises(BackendError, match='JVM_OUT_OF_MEMORY_REPORTED' if oom else 'UNCLASSIFIED'):
            session._exchange('probe', Cancellation(), 1)
        assert (session.process is None) is oom
    finally:
        session._dispose()


@pytest.mark.parametrize('broken_pipe', [False, True])
def test_abrupt_exit_is_not_assumed_oom(broken_pipe):
    session = JebSession(Settings(jvm_heap_mib=1024))
    session._directory = tempfile.TemporaryDirectory()
    work = Path(session._directory.name)
    (work / 'process.log').write_text('Process terminated without a JVM memory message')
    process = Process()
    process.returncode = -9
    if broken_pipe:
        class Pipe(io.StringIO):
            def write(self, text):
                raise BrokenPipeError()
        process.stdin = Pipe()
    session.process = process
    with pytest.raises(BackendError, match='UNCLASSIFIED.*heap_limit_mib=1024; exit_code=-9'):
        session._exchange('probe', Cancellation(), 1)
    assert session.process is None and not work.exists()


@pytest.mark.parametrize('case', ['success', 'invalid', 'busy', 'save_failure'])
def test_gui_heap_preserves_result(browser, tmp_path, monkeypatch, case):
    workspace, _ = browser
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    old_settings, result, content = workspace.settings, workspace._result, workspace.content
    if case == 'save_failure':
        def fail(*args):
            raise OSError('denied')
        monkeypatch.setattr(Settings, 'save', fail)
    workspace._busy = case == 'busy'
    try:
        assert workspace.saveJvmHeap(1 if case == 'invalid' else 2048) is (case == 'success')
        assert workspace._result is result and workspace.content == content
        if case == 'success':
            assert workspace.app.backend.settings.jvm_heap_mib == Settings.load().jvm_heap_mib == 2048
        else:
            assert workspace.settings is old_settings
    finally:
        workspace._busy = False


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_live_lower_heap_and_restart():
    from analyzer.backends.jeb.backend import JebBackend
    fixture = Path(__file__).resolve().parents[1] / 'build/fixtures/flow-fixture.apk'
    with JebBackend(Settings(jvm_heap_mib=1024, cache_enabled=False)) as backend:
        program = backend.load(fixture, Cancellation())
        assert program.methods and '-Xmx1024m' in backend.session.process.args
        previous = backend.session.process
        backend.settings.jvm_heap_mib = 768
        backend.probe(Cancellation())
        assert previous.poll() is not None
        assert '-Xmx768m' in backend.session.process.args
