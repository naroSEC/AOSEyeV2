import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('inspect_raw_name', Path(__file__).resolve().parents[1] / 'tools/inspect_raw_name.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


@pytest.mark.parametrize('suffix', ['', ' PUBLIC'])
def test_name_with_obfuscated_path(suffix):
    text = 'Package name=test.app id=7f\n    resource 0x7f010001 raw/ca' + suffix + '\n      () (file) res/X.bin\n'
    assert tool.select_raw_name(text, '@raw/ca')['resource_id'] == 0x7f010001


@pytest.mark.parametrize('case', ['missing', 'duplicate', 'packages', 'wrong_package', 'bad_header', 'budget', 'reference'])
def test_reject_ambiguous_names(case):
    text = 'Package name=test.app id=7f\n    resource 0x7f010001 raw/ca\n'
    reference = '@raw/ca'
    if case == 'missing':
        reference = '@raw/missing'
    elif case == 'duplicate':
        text += '    resource 0x7f010002 raw/ca\n'
    elif case == 'packages':
        text += 'Package name=other.app id=80\n'
    elif case == 'wrong_package':
        text = text.replace('0x7f', '0x80')
    elif case == 'bad_header':
        text = text.replace('id=7f', 'id=unknown')
    elif case == 'budget':
        text = 'x' * (16 * 1024 * 1024 + 1)
    else:
        reference = '@package:raw/ca'
    with pytest.raises(ValueError):
        tool.select_raw_name(text, reference)


@pytest.mark.parametrize('case', ['ok', 'failure', 'oversized', 'cancel'])
def test_dump_process_guards(monkeypatch, case):
    from analyzer.app.jobs import Cancellation, Cancelled
    token = Cancellation()
    processes = []
    class Process:
        returncode = 1 if case == 'failure' else 0
        killed = False
        waited = False
        def __init__(self, command, **kwargs):
            assert command == ['aapt2', 'dump', 'resources', 'input.apk']
            kwargs['stdout'].write(b'x' * (16 * 1024 * 1024 + 1) if case == 'oversized' else b'resources')
            processes.append(self)
            if case == 'cancel':
                token.cancel()
        def poll(self):
            return None if case == 'cancel' and not self.killed else self.returncode
        def kill(self):
            self.killed = True
        def wait(self):
            self.waited = True
    monkeypatch.setattr(tool.subprocess, 'Popen', Process)
    if case == 'ok':
        assert tool.dump_resources('aapt2', 'input.apk', token) == 'resources'
    else:
        with pytest.raises(Cancelled if case == 'cancel' else ValueError):
            tool.dump_resources('aapt2', 'input.apk', token)
    assert processes[0].waited
    if case == 'cancel':
        assert processes[0].killed
