from zipfile import ZipFile

import pytest
from defusedxml.common import DefusedXmlException

from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.analyzers.manifest import analyze_manifest
from analyzer.analyzers.storage_config import analyze_storage_config, parse_rules


def manifest():
    return analyze_manifest('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test">
    <application android:fullBackupContent="@xml/backup"><provider android:name=".Files" android:exported="false">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/paths"/>
    <path-permission android:pathPrefix="/docs" android:readPermission="test.READ"/>
    </provider></application></manifest>''')[0]


def test_provider_and_backup_inventory(tmp_path):
    path = tmp_path / 'test.apk'
    with ZipFile(path, 'w') as archive:
        archive.writestr('res/xml/paths.xml', '<paths><root-path name="root" path="."/><files-path name="images" path="images/"/></paths>')
        archive.writestr('res/xml/backup.xml', '<full-backup-content><exclude domain="sharedpref" path="tokens.xml"/></full-backup-content>')
    info = manifest()
    assert info['components'][0]['path_permissions'][0]['readPermission'] == 'test.READ'
    inventory, findings, diagnostics = analyze_storage_config(path, info, Cancellation())
    assert not diagnostics and len(findings) == 1 and findings[0].type == 'REVIEW'
    assert inventory['resources'][0]['paths'][1]['review_reasons'] == []
    assert inventory['resources'][1]['transports'][0]['selection'] == 'platform-default-minus-excludes'


@pytest.mark.parametrize('xml', ['<bad/>', '<paths><unknown name="x"/></paths>',
    '<paths><files-path name="x"/><files-path name="x"/></paths>',
    '<!DOCTYPE x [<!ENTITY e "expanded">]><paths>&e;</paths>'])
def test_invalid_paths(xml):
    with pytest.raises((ValueError, DefusedXmlException)):
        parse_rules(xml.encode(), 'fileprovider', Cancellation())


def test_backup_transport_separation():
    value = parse_rules(b'<data-extraction-rules><cloud-backup disableIfNoEncryptionCapabilities="true"><include domain="database" path="public.db"/></cloud-backup><device-transfer><exclude domain="database" path="secret.db"/></device-transfer></data-extraction-rules>', 'dataExtractionRules', Cancellation())
    assert value['transports'][0]['selection'] == 'explicit-includes'
    assert value['transports'][1]['selection'] == 'platform-default-minus-excludes'
    assert value['transports'][0]['attributes']['disableIfNoEncryptionCapabilities'] == 'true'


@pytest.mark.parametrize('kind', ['qualified', 'duplicate', 'missing'])
def test_ambiguous_resource_does_not_fallback(tmp_path, kind):
    path = tmp_path / 'test.apk'
    with ZipFile(path, 'w') as archive:
        if kind != 'missing':
            archive.writestr('res/xml/paths.xml', '<paths/>')
            if kind == 'duplicate':
                with pytest.warns(UserWarning, match='Duplicate name'):
                    archive.writestr('res/xml/paths.xml', '<paths/>')
            else:
                archive.writestr('res/xml-v31/paths.xml', '<paths/>')
    info = manifest()
    info['application'] = {}
    value, _, diagnostics = analyze_storage_config(path, info, Cancellation(),
        lambda *a: pytest.fail('Must not bypass ZIP ambiguity'))
    assert value['resources'][0]['status'] == 'UNKNOWN' and diagnostics


def test_numeric_default_decoder_and_cancel(tmp_path):
    info = manifest()
    info['application'] = {}
    info['components'][0]['metadata'][0]['resource'] = '@7f010000'
    value, _, diagnostics = analyze_storage_config(tmp_path / 'unused.apk', info, Cancellation(),
        lambda *a: dict(xml='<paths><files-path name="images" path="images/"/></paths>', resource='res/xml/renamed.xml'))
    assert value['resources'][0]['configuration'] == 'default-only' and diagnostics
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        analyze_storage_config(tmp_path / 'unused.apk', info, token)


def test_corrupt_archive_is_unknown(tmp_path):
    path = tmp_path / 'corrupt.apk'
    path.write_bytes(b'not a ZIP')
    inventory, findings, diagnostics = analyze_storage_config(path, manifest(), Cancellation())
    assert not findings and len(diagnostics) == 2
    assert all(row['status'] == 'UNKNOWN' for row in inventory['resources'])


def test_empty_xml_still_honors_cancellation():
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        parse_rules(b'<paths/>', 'fileprovider', token)


@pytest.mark.parametrize('case', ['mapped', 'qualified', 'duplicate', 'cancel', 'failure'])
def test_missing_name_mapping_only(tmp_path, case):
    path = tmp_path / 'test.apk'
    with ZipFile(path, 'w') as archive:
        archive.writestr('res/zz.xml', b'compiled')
        if case == 'qualified':
            archive.writestr('res/xml-v31/paths.xml', '<paths/>')
        if case == 'duplicate':
            archive.writestr('res/xml/paths.xml', '<paths/>')
            with pytest.warns(UserWarning):
                archive.writestr('res/xml/paths.xml', '<paths/>')
    info = manifest()
    info['application'] = {}
    def resolve(ref, token):
        assert case not in ('qualified', 'duplicate')
        if case == 'cancel':
            raise Cancelled()
        if case == 'failure':
            raise ValueError('No mapping')
        return dict(xml='<paths><root-path name="root" path="."/></paths>', resource='res/zz.xml',
                    resource_id=0x7f150003, reference=ref, name_origin='aapt2 dump resources', package='test')
    if case == 'cancel':
        with pytest.raises(Cancelled):
            analyze_storage_config(path, info, Cancellation(), named_resolver=resolve)
        return
    value, findings, diagnostics = analyze_storage_config(path, info, Cancellation(), named_resolver=resolve)
    row = value['resources'][0]
    assert diagnostics
    if case == 'mapped':
        assert row['resource'] == 'res/zz.xml' and row['mapping']['resource_id'] == 0x7f150003
        assert row['configuration'] == 'default-only' and findings[0].type == 'REVIEW'
    else:
        assert row['status'] == 'UNKNOWN' and not findings


@pytest.mark.parametrize('case', ['valid', 'duplicate', 'package', 'wrong_type'])
def test_xml_name_selection(case):
    from analyzer.backends.raw_names import select_resource_name
    text = 'Package name=test id=7f\n    resource 0x7f150003 xml/paths\n'
    if case == 'duplicate':
        text += '    resource 0x7f150004 xml/paths\n'
    elif case == 'package':
        text = text.replace('id=7f', 'id=80')
    elif case == 'wrong_type':
        text = text.replace('xml/paths', 'raw/paths')
    if case == 'valid':
        assert select_resource_name(text, '@xml/paths', 'xml')['resource_id'] == 0x7f150003
    else:
        with pytest.raises(ValueError):
            select_resource_name(text, '@xml/paths', 'xml')


@pytest.mark.parametrize('case', ['valid', 'disabled', 'wrong_id', 'wrong_config', 'late_cancel'])
def test_backend_named_xml_identity(tmp_path, monkeypatch, case):
    from analyzer.backends.jeb.backend import JebBackend
    from analyzer.app.settings import Settings
    from analyzer.backends import raw_names
    executable = tmp_path / 'aapt2.exe'
    executable.write_bytes(b'not executed')
    backend = JebBackend(Settings(aapt2_path='' if case == 'disabled' else str(executable)))
    monkeypatch.setattr(backend, '_input_request', lambda token: {})
    monkeypatch.setattr(raw_names, 'dump_resources', lambda *a: 'Package name=test id=7f\n    resource 0x7f150003 xml/paths\n')
    token = Cancellation()
    def decode(reference, cancel):
        assert reference == '@7f150003'
        if case == 'late_cancel':
            cancel.cancel()
        return dict(resource_id=0 if case == 'wrong_id' else 0x7f150003,
                    configuration='device' if case == 'wrong_config' else 'default-only')
    monkeypatch.setattr(backend, 'resolve_network_xml', decode)
    if case == 'valid':
        result = backend.resolve_named_storage_xml('@xml/paths', token)
        assert result['reference'] == '@xml/paths' and result['package'] == 'test'
    else:
        with pytest.raises(Cancelled if case == 'late_cancel' else ValueError):
            backend.resolve_named_storage_xml('@xml/paths', token)
