import hashlib
import importlib.util
import json
from pathlib import Path
from zipfile import ZipFile

import pytest
from analyzer.app.settings import Settings

spec = importlib.util.spec_from_file_location('release_gate', Path(__file__).parents[1] / 'tools/release_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def evidence(tmp_path):
    source = tmp_path / 'src/analyzer'
    source.mkdir(parents=True)
    (source / '__init__.py').write_text('x = 1\n', encoding='utf-8')
    wheel = tmp_path / 'test.whl'
    with ZipFile(wheel, 'w') as archive:
        archive.write(source / '__init__.py', 'analyzer/__init__.py')
        archive.writestr('aoseye-0.1.0.dist-info/METADATA',
            'License-Expression: MIT\nLicense-File: LICENSE\nLicense-File: THIRD_PARTY_NOTICES.md\n\n')
        for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
            local = tmp_path / name
            local.write_text('synthetic notice\n', encoding='utf-8')
            archive.write(local, 'aoseye-0.1.0.dist-info/licenses/' + name)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    install = tmp_path / 'install.json'
    report = {'passed': True, 'sha256': digest,
              'checks': [{'name': name, 'returncode': 0} for name in sorted(gate.CHECKS)]}
    install.write_text(json.dumps(report), encoding='utf-8')
    regression = tmp_path / 'tests.xml'
    regression.write_text(f'<testsuites><testsuite name="aoseye.{digest}" tests="1" errors="0" failures="0" skipped="0">'
                          '<testcase name="test_one"/></testsuite></testsuites>', encoding='utf-8')
    acceptance = tmp_path / 'acceptance.json'
    approval = {'wheel_sha256': digest, **{k: {'approved': True, 'reviewer': 'synthetic test reviewer',
        'evidence': 'synthetic unit-test evidence, not real approval'} for k in gate.APPROVALS}}
    acceptance.write_text(json.dumps(approval), encoding='utf-8')
    return wheel, install, regression, acceptance, tmp_path


def test_consistent_synthetic_evidence_requires_owner_release_review(tmp_path):
    result = gate.assess(*evidence(tmp_path))
    assert not result['blockers'] and result['status'] == 'READY_FOR_OWNER_RELEASE_REVIEW'


@pytest.mark.parametrize('change', ['install_hash', 'install_failed', 'missing_check', 'duplicate_check',
    'test_hash', 'skipped', 'source_changed', 'approval_hash', 'not_approved', 'no_reviewer', 'license_changed'])
def test_fail_closed_on_incomplete_or_different_evidence(tmp_path, change):
    args = evidence(tmp_path)
    _, install, regression, acceptance, root = args
    if change.startswith('install') or change in ('missing_check', 'duplicate_check'):
        value = json.loads(install.read_text())
        if change == 'install_hash': value['sha256'] = 'old'
        elif change == 'install_failed': value['passed'] = False
        elif change == 'missing_check': value['checks'].pop()
        else: value['checks'][-1] = value['checks'][0]
        install.write_text(json.dumps(value))
    elif change in ('test_hash', 'skipped'):
        text = regression.read_text()
        regression.write_text(text.replace('aoseye.', 'old.') if change == 'test_hash' else text.replace('skipped="0"', 'skipped="1"'))
    elif change == 'source_changed':
        (root / 'src/analyzer/__init__.py').write_text('changed')
    elif change == 'license_changed':
        (root / 'LICENSE').write_text('changed')
    else:
        value = json.loads(acceptance.read_text())
        if change == 'approval_hash': value['wheel_sha256'] = 'old'
        elif change == 'not_approved': value['licensing']['approved'] = False
        else: value['licensing']['reviewer'] = ''
        acceptance.write_text(json.dumps(value))
    assert gate.assess(*args)['status'] == 'BLOCKED'


def test_jeb_environment_is_evaluated_for_each_new_setting(monkeypatch):
    monkeypatch.setenv('AOSEYE_JEB_PATH', 'C:/first-jeb')
    assert Settings().jeb_path == 'C:/first-jeb'
    monkeypatch.setenv('AOSEYE_JEB_PATH', 'C:/second-jeb')
    assert Settings().jeb_path == 'C:/second-jeb'
    monkeypatch.delenv('AOSEYE_JEB_PATH')
    assert Settings().jeb_path == ''


def test_unconfigured_backend_never_uses_working_directory(monkeypatch):
    from analyzer.backends.jeb.backend import JebBackend
    from analyzer.backends.base import BackendError
    from analyzer.app.jobs import Cancellation
    import subprocess
    monkeypatch.delenv('AOSEYE_JEB_PATH', raising=False)
    def forbidden(*args, **kwargs):
        pytest.fail('Unconfigured backend must not launch Java')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    with JebBackend(Settings()) as backend:
        assert backend.home is None and backend.session.home is None
        with pytest.raises(BackendError, match='JEB path is not configured'):
            backend.probe(Cancellation())


def test_saved_installation_path_preserved(tmp_path, monkeypatch):
    path = tmp_path / 'settings.json'
    Settings(jeb_path='C:/existing-jeb').save(path)
    monkeypatch.setenv('AOSEYE_JEB_PATH', 'C:/new-default')
    assert Settings.load(path).jeb_path == 'C:/existing-jeb'
