import json
import io
from pathlib import Path
import pytest
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.settings import Settings
from analyzer.backends.base import BackendError
from analyzer.backends.jeb.backend import JebBackend
import analyzer.backends.jeb.session as module


def fake_install(tmp_path):
    jar = tmp_path / 'bin/app/jeb.jar'
    jar.parent.mkdir(parents=True)
    jar.touch()
    return JebBackend(Settings(jeb_path=str(tmp_path)))


def test_missing_jeb_is_explicit(tmp_path):
    with pytest.raises(BackendError, match='not found'):
        JebBackend(Settings(jeb_path=str(tmp_path))).probe(Cancellation())


def test_explicit_java_wins_over_bundled_runtime(tmp_path, processes):
    backend = fake_install(tmp_path)
    bundled = tmp_path / 'bin/runtime/bin/java.exe'
    bundled.parent.mkdir(parents=True)
    bundled.touch()
    backend.session.java = str(tmp_path / 'selected-java.exe')
    with backend:
        backend.probe(Cancellation())
        assert processes[0].command[0] == backend.session.java


def test_failed_java_launch_cleans_session_and_can_retry(tmp_path, monkeypatch):
    backend = fake_install(tmp_path)
    def fail(*args, **kwargs):
        raise FileNotFoundError('missing executable')
    monkeypatch.setattr(module.subprocess, 'Popen', fail)
    with pytest.raises(BackendError, match='Could not start Java executable'):
        backend.probe(Cancellation())
    assert backend.session.process is None
    assert backend.session._directory is None and backend.session._log is None
    monkeypatch.setattr(module.subprocess, 'Popen', FakeProcess)
    FakeProcess.respond, FakeProcess.wrong_id = True, False
    with backend:
        assert backend.probe(Cancellation())['status'] == 'Connected'


class FakeProcess:
    instances = []
    respond = True
    wrong_id = False
    def __init__(self, command, **kwargs):
        self.returncode = None
        self.pid = 1234
        self.command, self.kwargs = command, kwargs
        self.terminated = False
        self.operations = []
        self.instances.append(self)
        owner = self
        class Input(io.StringIO):
            def write(self, line):
                request = json.loads(Path(json.loads(line)['request']).read_text(encoding='utf-8'))
                owner.operations.append(request['operation'])
                if owner.respond:
                    Path(request['output']).write_text(json.dumps({'schema_version': 1, 'ok': True,
                        'request_id': 'wrong' if owner.wrong_id else request['request_id'],
                        'capabilities': {'core': 'verified'}}), encoding='utf-8')
                if request['operation'] == 'shutdown':
                    owner.returncode = 0
                return len(line)
        self.stdin = Input()
    def poll(self):
        return self.returncode
    def terminate(self):
        self.terminated = True
        self.returncode = -1
    def wait(self, **kwargs):
        return self.returncode


@pytest.fixture
def processes(monkeypatch):
    FakeProcess.instances = []
    FakeProcess.respond = True
    FakeProcess.wrong_id = False
    monkeypatch.setattr(module.subprocess, 'Popen', FakeProcess)
    return FakeProcess.instances


def test_no_shell_and_session_reused(tmp_path, processes):
    with fake_install(tmp_path / 'JEB with spaces') as backend:
        assert backend.probe(Cancellation())['status'] == 'Connected'
        assert backend.probe(Cancellation())['status'] == 'Connected'
        assert len(processes) == 1
        assert isinstance(processes[0].command, list)
        assert processes[0].command[-1] == str(backend.home)
        assert not processes[0].kwargs.get('shell')
    assert processes[0].operations == ['probe', 'probe', 'shutdown']
    assert not processes[0].terminated


def test_cancellation_terminates_child(tmp_path, processes):
    backend = fake_install(tmp_path)
    cancel = Cancellation()
    backend.probe(cancel)
    cancel.cancel()
    with pytest.raises(Cancelled):
        backend.probe(cancel)
    assert processes[0].terminated
    assert backend.session.pid is None
    backend.probe(Cancellation())
    assert len(processes) == 2
    backend.close()


def test_timeout_terminates_child(tmp_path, processes):
    backend = fake_install(tmp_path)
    backend.session.timeout = 0
    FakeProcess.respond = False
    with pytest.raises(BackendError, match='timed out'):
        backend.probe(Cancellation())
    assert processes[0].terminated
    assert backend.session.pid is None


def test_wrong_response_id_discards_session(tmp_path, processes):
    backend = fake_install(tmp_path)
    FakeProcess.wrong_id = True
    with pytest.raises(BackendError, match='request ID'):
        backend.probe(Cancellation())
    assert processes[0].terminated


def test_normalized_indexes(flow_program):
    backend = JebBackend(Settings())
    backend.program = flow_program
    from conftest import ENTRY, HELPER
    assert ENTRY in backend.get_callers(HELPER)
    assert HELPER in backend.get_callees(ENTRY)
    assert backend.get_xrefs(HELPER)[0]['offset'] == 20
    assert backend.get_method(ENTRY).signature == ENTRY
    assert backend.get_call_graph(ENTRY)['edges']
    with pytest.raises(BackendError, match='original APK'):
        backend.get_ast(ENTRY)
