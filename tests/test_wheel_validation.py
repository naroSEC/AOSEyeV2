import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('failure', [None, 'install', 'gui-smoke', 'export-html', 'export-verify'])
def test_wheel_validation_isolates_environment_and_records_failure(tmp_path, monkeypatch, failure):
    path = Path(__file__).resolve().parents[1] / 'tools/validate_wheel_install.py'
    spec = importlib.util.spec_from_file_location('wheel_validation', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / 'validation'
    root.mkdir()
    wheel, apk, jeb = tmp_path / 'a.whl', tmp_path / 'fixture.apk', tmp_path / 'jeb'
    wheel.write_bytes(b'wheel')
    apk.write_bytes(b'fixture')
    jeb.mkdir()
    monkeypatch.setattr(sys, 'argv', [str(path), str(wheel), '--jeb-path', str(jeb), '--apk', str(apk)])
    monkeypatch.setattr(module.tempfile, 'mkdtemp', lambda **kw: str(root))
    monkeypatch.setattr(module.venv.EnvBuilder, 'create', lambda self, target: None)
    monkeypatch.setenv('PYTHONPATH', 'unwanted-source')
    monkeypatch.setenv('LOCALAPPDATA', 'original-settings')
    labels = iter(['install', 'dependencies', 'installed-files', 'console-help',
                   'module-help', 'gui-smoke', 'probe', 'inspect', 'analyze', 'reopen',
                   'export-html', 'export-csv', 'export-ir-json', 'export-verify'])
    commands = []

    def run(command, **kwargs):
        label = next(labels)
        commands.append(command)
        assert kwargs['cwd'] == root
        assert 'PYTHONPATH' not in kwargs['env']
        assert kwargs['env']['LOCALAPPDATA'] == str(root / 'userdata')
        assert kwargs['env']['QT_QPA_PLATFORM'] == 'offscreen'
        code = 1 if label == failure else 2 if label == 'analyze' else 0
        return subprocess.CompletedProcess(command, code, 'out', 'err')

    monkeypatch.setattr(module.subprocess, 'run', run)
    if failure:
        with pytest.raises(RuntimeError, match=failure):
            module.main()
    else:
        module.main()
    report = json.loads((root / 'validation.json').read_text())
    assert report['passed'] is (failure is None)
    assert report['checks'][-1]['name'] == (failure or 'export-verify')
    if failure is None:
        assert len(report['checks']) == 14
    assert module.os.environ['LOCALAPPDATA'] == 'original-settings'
    assert wheel.read_bytes() == b'wheel' and apk.read_bytes() == b'fixture'
    assert all(str(root / 'venv') in command[0] for command in commands)
