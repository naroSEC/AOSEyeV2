from copy import deepcopy
from pathlib import Path

import pytest

from analyzer.app.settings import Settings
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.backends.jeb.backend import JebBackend, file_hash
from analyzer.backends import raw_names
from test_dex_browser import browser


@pytest.mark.parametrize('value', ['aapt2', 'relative/aapt2.exe', '\x00', '\r\n', 42])
def test_bad_setting(value):
    with pytest.raises(ValueError):
        Settings(aapt2_path=value)


def test_old_settings_and_roundtrip(tmp_path):
    path = tmp_path / 'settings.json'
    path.write_text('{}', encoding='utf-8')
    assert Settings.load(path).aapt2_path == ''
    settings = Settings(aapt2_path=str(tmp_path / 'tool.exe'))
    settings.save(path)
    assert Settings.load(path).aapt2_path == settings.aapt2_path


@pytest.mark.parametrize('case', ['enabled', 'disabled', 'missing', 'dump_failure', 'cancel', 'changed'])
def test_backend_optional_name_resolution(tmp_path, monkeypatch, case):
    apk = tmp_path / 'app.apk'
    apk.write_bytes(b'fixture')
    executable = tmp_path / 'aapt2.exe'
    if case != 'missing':
        executable.write_bytes(b'not executed')
    backend = JebBackend(Settings(aapt2_path='' if case == 'disabled' else str(executable)))
    backend.input_path, backend.input_sha256 = apk, file_hash(apk)
    calls = []
    def dump(*args):
        calls.append('dump')
        if case == 'dump_failure':
            raise ValueError('bad output')
        if case == 'cancel':
            raise Cancelled()
        if case == 'changed':
            apk.write_bytes(b'changed')
        return 'Package name=app.test id=7f\n    resource 0x7f010001 raw/ca\n'
    def run(*args, **kwargs):
        calls.append('jeb')
        assert kwargs['resource_type'] == 'raw'
        return dict(configuration='default', resources=[dict(id=0x7f010001, type=3, path='res/renamed.bin')])
    monkeypatch.setattr(raw_names, 'dump_resources', dump)
    monkeypatch.setattr(backend, '_run', run)
    try:
        if case in ('enabled', 'disabled'):
            value = backend.resolve_ca_resource('@raw/ca', Cancellation())
            if case == 'disabled':
                assert value == dict(status='NAMED_RESOLUTION_DISABLED') and not calls
            else:
                assert value['reference'] == '@raw/ca' and value['resource'] == 'res/renamed.bin'
                assert calls == ['dump', 'jeb']
        else:
            with pytest.raises(Cancelled if case == 'cancel' else (ValueError, RuntimeError)):
                backend.resolve_ca_resource('@raw/ca', Cancellation())
            assert 'jeb' not in calls
    finally:
        backend.close()


@pytest.mark.parametrize('case', ['save', 'disable', 'missing', 'save_failure', 'busy'])
def test_gui_aapt2_setting_preserves_evidence(browser, tmp_path, monkeypatch, case):
    workspace, _ = browser
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'userdata'))
    executable = tmp_path / 'aapt2.exe'
    executable.write_bytes(b'not executed')
    before = deepcopy(workspace._result.to_dict())
    content, settings = workspace.content, workspace.settings
    if case == 'save_failure':
        def fail(*args):
            raise OSError('test denied')
        monkeypatch.setattr(Settings, 'save', fail)
    workspace._busy = case == 'busy'
    try:
        target = '' if case == 'disable' else str(tmp_path / 'missing.exe') if case == 'missing' else str(executable)
        saved = workspace.saveAapt2(target)
        assert saved is (case in ('save', 'disable'))
        if saved:
            assert workspace.settings.aapt2_path == target
            assert workspace.app.backend.settings.aapt2_path == target
            assert Settings.load().aapt2_path == target
        else:
            assert workspace.settings is settings
        assert workspace._result.to_dict() == before and workspace.content == content
    finally:
        workspace._busy = False
