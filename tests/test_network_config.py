from zipfile import ZipFile

import pytest

from analyzer.analyzers.network_config import analyze_network_config, parse_cleartext
from analyzer.analyzers.manifest import analyze_manifest
from analyzer.app.jobs import Cancellation, Cancelled


def test_inheritance_and_explicit_override():
    xml = b'''<network-security-config><base-config cleartextTrafficPermitted="false"/>
    <domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="true">Example.com</domain>
    <domain-config cleartextTrafficPermitted="false"><domain>private.example.com</domain></domain-config>
    </domain-config></network-security-config>'''
    result = parse_cleartext(xml, 28, Cancellation())
    assert result['base_cleartext_permitted'] is False
    assert [d['cleartext_permitted'] for d in result['domains']] == [True, False]
    assert result['domains'][0]['include_subdomains'] is True


@pytest.mark.parametrize('target, expected', [(27, True), (28, False), (None, None)])
def test_target_default(target, expected):
    result = parse_cleartext(b'<network-security-config/>', target, Cancellation())
    assert result['base_cleartext_permitted'] is expected


@pytest.mark.parametrize('kind', ['plain', 'binary', 'missing', 'variant', 'numeric', 'malformed',
                                  'boolean-resource', 'duplicate-domain', 'entity'])
def test_resource_resolution_is_conservative(tmp_path, kind):
    apk = tmp_path / 'test.apk'
    content = b'<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>'
    if kind == 'binary':
        content = b'\x03\x00\x08\x00binary'
    elif kind == 'malformed':
        content = b'<network-security-config>'
    elif kind == 'boolean-resource':
        content = content.replace(b'"true"', b'"@bool/cleartext"')
    elif kind == 'duplicate-domain':
        content = b'<network-security-config><domain-config><domain>a.com</domain><domain>a.com</domain></domain-config></network-security-config>'
    elif kind == 'entity':
        content = b'<!DOCTYPE a [<!ENTITY x "value">]><network-security-config>&x;</network-security-config>'
    with ZipFile(apk, 'w') as archive:
        if kind != 'missing':
            archive.writestr('res/xml/network.xml', content)
        if kind == 'variant':
            archive.writestr('res/xml-v28/network.xml', content)
    manifest = dict(target_sdk=28, application={'networkSecurityConfig': '@0x7f010001' if kind == 'numeric' else '@xml/network'})
    info, findings, diagnostics = analyze_network_config(apk, manifest, Cancellation())
    assert info['status'] == ('PARSED' if kind == 'plain' else 'UNKNOWN')
    assert bool(diagnostics) == (kind != 'plain')
    assert findings and all(f.type == 'REVIEW' for f in findings)


def test_manifest_flag_with_nsc_is_not_standalone_weakness():
    _, findings = analyze_manifest('<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/network"/></manifest>')
    flag = next(f for f in findings if f.rule_id == 'AOS-MANIFEST-USESCLEARTEXTTRAFFIC')
    assert flag.type == 'REVIEW'


def test_cancelled_resource_read(tmp_path):
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        analyze_network_config(tmp_path / 'absent', {'application': {'networkSecurityConfig': '@xml/network'}}, token)


@pytest.mark.parametrize('binary', [False, True])
def test_application_policy_roundtrip(tmp_path, binary):
    from analyzer.app.application import AnalysisApplication
    from analyzer.app.settings import Settings
    from analyzer.app.project_manager import save_project, open_project
    from analyzer.core.models import Program
    from test_application import FixtureBackend
    apk = tmp_path / 'policy.apk'
    with ZipFile(apk, 'w') as archive:
        archive.writestr('AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk android:targetSdkVersion="28"/><application android:allowBackup="false" android:networkSecurityConfig="@xml/network"/></manifest>')
        archive.writestr('res/xml/network.xml', b'\x03\x00binary' if binary else b'<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>')
    result = AnalysisApplication(Settings(), FixtureBackend(Program())).analyze(apk, Cancellation())
    assert result.manifest['network_security_config']['status'] == ('UNKNOWN' if binary else 'PARSED')
    if binary:
        assert not result.complete and any('configuration unresolved' in d for d in result.diagnostics)
    else:
        assert not any(f.rule_id.startswith('AOS-NETWORK-CONFIG') for f in result.findings)
    project = tmp_path / 'policy.json'
    save_project(project, result)
    assert open_project(project).manifest == result.manifest
