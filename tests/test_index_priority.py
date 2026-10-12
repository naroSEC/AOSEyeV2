import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from analyzer.backends.index_priority import manifest_hints
from analyzer.app.settings import Settings
from analyzer.app.jobs import Cancellation

path = Path(__file__).resolve().parents[1] / 'src/analyzer/backends/jeb/scripts/IndexPriority.py'
spec = importlib.util.spec_from_file_location('index_priority', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def item(signature):
    return SimpleNamespace(getSignature=lambda _: signature)


def test_stable_exact_package_and_boundary_selection():
    names = ['Lsdk/A;->a()V', 'Lapp/mainly/B;->b()V', 'Lapp/main/C;->a()V',
             'Loutside/Entry;->z()V', 'Loutside/Entry;->a()V', 'Lapp/main/D;->a()V']
    selected = module.select_priority([item(s) for s in names], 4, ['Loutside/Entry;'], 'Lapp/main/')
    assert [x.getSignature(False) for x in selected] == [names[3], names[4], names[2], names[5]]
    assert module.select_priority([item('Lx;')], 0, [], '') == []


def test_no_hints_keeps_order_and_duplicate_origins():
    rows = [item('Lsame;'), item('Lsame;'), item('Lz;')]
    assert module.select_priority(rows, 2, [], '') == rows[:2]


def test_manifest_relative_alias_and_application_hints():
    hints = manifest_hints('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="app.main">
    <application android:name="App"><activity android:name=".Main"/>
    <activity-alias android:name=".Alias" android:targetActivity="outside.Entry"/>
    <receiver android:name="@string/dynamic"/><service android:name=".Disabled" android:enabled="false"/>
    </application></manifest>''')
    assert hints['priority_classes'] == ['Lapp/main/App;', 'Lapp/main/Disabled;', 'Lapp/main/Main;', 'Loutside/Entry;']
    assert hints['priority_package'] == 'Lapp/main/'


@pytest.mark.parametrize('data', ['<bad', '<other/>', '<!DOCTYPE x [<!ENTITY e "bad">]><manifest>&e;</manifest>', 'x' * (1024 * 1024 + 1)], ids=['malformed', 'root', 'entity', 'budget'])
def test_invalid_manifest(data):
    with pytest.raises(ValueError):
        manifest_hints(data)


def test_invalid_policy():
    with pytest.raises(ValueError):
        Settings(index_order='guess')
    assert Settings().index_order == 'native'


@pytest.mark.parametrize('failure', [False, True])
def test_backend_policy_cache_and_fallback(tmp_path, monkeypatch, failure):
    from analyzer.backends.jeb.backend import JebBackend
    from analyzer.backends.base import BackendError
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    apk, records = tmp_path / 'input.apk', tmp_path / 'records'
    apk.write_bytes(b'test')
    records.write_bytes(b'')
    calls = []
    with JebBackend(Settings()) as backend:
        monkeypatch.setattr(backend, 'probe', lambda *args: {})
        def run(operation, token, receive=None, **kwargs):
            calls.append((operation, kwargs))
            if operation == 'resources':
                if failure:
                    raise BackendError('fixture unavailable')
                return {'manifest': '<manifest package="app.main"><application/></manifest>'}
            return receive({'program': {}}, records)
        monkeypatch.setattr(backend, '_run', run)
        backend.load(apk, Cancellation())
        backend.load(apk, Cancellation())
        assert [op for op, _ in calls] == ['index']
        backend.settings.index_order = 'manifest-first'
        result = backend.load(apk, Cancellation())
        assert [op for op, _ in calls] == ['index', 'resources', 'index']
        assert calls[-1][1]['index_order'] == ('native' if failure else 'manifest-first')
        if failure:
            assert 'native order used' in result.diagnostics[0]
        else:
            assert calls[-1][1]['priority_package'] == 'Lapp/main/'
        cached = backend.load(apk, Cancellation())
        assert len(calls) == 3 and cached.diagnostics == result.diagnostics


def test_hint_cancellation_does_not_fall_back(tmp_path, monkeypatch):
    from analyzer.backends.jeb.backend import JebBackend
    from analyzer.app.jobs import Cancelled
    apk = tmp_path / 'input.apk'
    apk.write_bytes(b'test')
    with JebBackend(Settings(index_order='manifest-first', cache_enabled=False)) as backend:
        monkeypatch.setattr(backend, 'probe', lambda *args: {})
        previous = backend.program
        def run(operation, token, **kwargs):
            assert operation == 'resources'
            raise Cancelled('fixture cancellation')
        monkeypatch.setattr(backend, '_run', run)
        with pytest.raises(Cancelled):
            backend.load(apk, Cancellation())
        assert backend.program is previous


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_live_class_priority_under_count_limit():
    from analyzer.backends.jeb.backend import JebBackend, file_hash
    fixture = Path(__file__).resolve().parents[1] / 'build/fixtures/flow-fixture.apk'
    with JebBackend(Settings(jvm_heap_mib=1024, cache_enabled=False)) as backend:
        backend.input_path, backend.input_sha256 = fixture, file_hash(fixture)
        def receive(response, records):
            return response
        result = backend._run('index', Cancellation(), receive=receive, **backend._input_request(),
            max_index_entries=1, index_order='manifest-first', priority_classes=['Ltest/Navigation;'], priority_package='Ltest/')
        assert result['program']['class_index'][0]['signature'] == 'Ltest/Navigation;'
        assert result['program']['method_index'][0]['signature'].startswith('Ltest/Navigation;->')
        assert any('Declaration index budget exhausted' in d for d in result['program']['diagnostics'])
