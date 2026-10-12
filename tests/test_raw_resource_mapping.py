import os
from pathlib import Path
from zipfile import ZipFile

import pytest

from analyzer.analyzers.network_certificates import select_raw_resource, inspect_trust_resources
from analyzer.analyzers.network_trust import parse_trust
from analyzer.app.jobs import Cancellation, Cancelled


def inventory(**row):
    return dict(configuration='default', resources=[dict(id=0x7f010001, type=3, path='res/a.bin', **row)])


@pytest.mark.parametrize('ref', ['@0x7f010001', '@7f010001'])
def test_numeric_mapping(ref):
    value = select_raw_resource(inventory(), ref)
    assert value['resource'] == 'res/a.bin' and value['configuration'] == 'default-only'


@pytest.mark.parametrize('path', ['../ca', 'res/../ca', 'res//ca', 'res/./ca', 'res/ca\\x', 'res/c:x', 'res/ca\x00', '/res/ca', None])
def test_bad_paths(path):
    data = inventory()
    data['resources'][0]['path'] = path
    with pytest.raises(ValueError):
        select_raw_resource(data, '@7f010001')


@pytest.mark.parametrize('case', ['alias', 'complex', 'duplicate', 'missing', 'bad_id', 'budget', 'configuration'])
def test_bad_inventory(case):
    data = inventory()
    if case in ('alias', 'complex'):
        data['resources'][0]['type'] = 1 if case == 'alias' else None
    elif case == 'duplicate':
        data['resources'] *= 2
    elif case == 'missing':
        data['resources'] = []
    elif case == 'bad_id':
        data['resources'][0]['id'] = '0x7f010001'
    elif case == 'budget':
        data['resources'] *= 4097
    else:
        data['configuration'] = 'device'
    with pytest.raises(ValueError):
        select_raw_resource(data, '@7f010001')


def trust():
    return parse_trust('<network-security-config><base-config><trust-anchors>'
        '<certificates src="@7f010001"/></trust-anchors></base-config></network-security-config>',
        28, False, Cancellation())


@pytest.mark.parametrize('case', ['mapped', 'missing', 'duplicate', 'oversized', 'failure', 'cancel', 'wrong_id', 'bad_path'])
def test_mapped_zip_guards(tmp_path, case):
    apk = tmp_path / 'test.apk'
    with ZipFile(apk, 'w') as archive:
        if case != 'missing':
            archive.writestr('res/a.bin', b'x' * (1024 * 1024 + 1) if case == 'oversized' else b'not a certificate')
        if case == 'duplicate':
            with pytest.warns(UserWarning):
                archive.writestr('res/a.bin', b'duplicate')
    def resolve(ref, token):
        if case == 'failure':
            raise RuntimeError('Unavailable')
        if case == 'cancel':
            raise Cancelled()
        value = select_raw_resource(inventory(), ref)
        if case == 'wrong_id':
            value['resource_id'] += 1
        if case == 'bad_path':
            value['resource'] = '../ca'
        return value
    value = trust()
    if case == 'cancel':
        with pytest.raises(Cancelled):
            inspect_trust_resources(apk, value, Cancellation(), resolve)
        return
    inspect_trust_resources(apk, value, Cancellation(), resolve)
    result = value['base_anchors'][0]['resource_inspection']
    assert result['status'] == 'UNKNOWN' and result['reason']
    if case == 'mapped':
        assert result['mapping'] == 'RESOURCE_TABLE_DEFAULT' and result['sha256']
    if case == 'oversized':
        assert 'budget' in result['reason'] and 'sha256' not in result


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_live_raw_table_mapping():
    from analyzer.backends.jeb.backend import JebBackend, file_hash
    from analyzer.app.settings import Settings
    root = Path(__file__).resolve().parents[1]
    samples = list((root / '.codex-remote-attachments').rglob('2-amospro_dev6.apk'))
    if not samples:
        pytest.skip('Local sample unavailable')
    with JebBackend(Settings()) as backend:
        backend.input_path = samples[0]
        backend.input_sha256 = file_hash(samples[0])
        token = Cancellation()
        data = backend._run('resources', token, **backend._input_request(token), resource_type='raw')
        rows = [r for r in data['resources'] if r['type'] == 3]
        assert rows, 'Expected raw resources in local sample'
        row = rows[0]
        mapped = backend.resolve_ca_resource('@%08x' % (row['id'] & 0xffffffff), token)
        assert mapped['resource'] == row['path']
        with ZipFile(samples[0]) as archive:
            assert len([e for e in archive.infolist() if e.filename == mapped['resource']]) == 1
        # This validates resource linkage, not that this arbitrary raw file is a CA.


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_live_optional_aapt2_named_mapping():
    from analyzer.backends.jeb.backend import JebBackend, file_hash
    from analyzer.app.settings import Settings
    root = Path(__file__).resolve().parents[1]
    samples = list((root / '.codex-remote-attachments').rglob('2-amospro_dev6.apk'))
    sdk_tool = Path(os.environ.get('LOCALAPPDATA', '')) / 'Android/Sdk/build-tools/35.0.0/aapt2.exe'
    # Tests may isolate LOCALAPPDATA; use an explicit override for that environment.
    executable = Path(os.environ.get('AOSEYE_TEST_AAPT2', str(sdk_tool)))
    if not samples or not executable.is_file():
        pytest.skip('Local APK/aapt2 fixture unavailable')
    with JebBackend(Settings(aapt2_path=str(executable.resolve()))) as backend:
        backend.input_path, backend.input_sha256 = samples[0], file_hash(samples[0])
        token = Cancellation()
        named = backend.resolve_ca_resource('@raw/zxing_beep', token)
        numeric = backend.resolve_ca_resource('@%08x' % named['resource_id'], token)
        assert named['resource'] == numeric['resource'] == 'res/raw/zxing_beep.ogg'
        assert named['configuration'] == 'default-only'
