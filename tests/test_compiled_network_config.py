import os
from pathlib import Path
from zipfile import ZipFile

import pytest

from analyzer.analyzers.network_config import analyze_network_config
from analyzer.app.jobs import Cancellation, Cancelled


@pytest.mark.parametrize('reference', ['@0x7f120006', '@7f120006', '@xml/network'])
def test_decoded_policy_is_default_only(tmp_path, reference):
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w') as z:
        z.writestr('res/xml/network.xml', b'\x03\x00binary')
    calls = []
    def resolve(ref, cancel):
        calls.append(ref)
        return dict(xml='<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>',
                    resource='res/xml/network.xml', resource_id=0x7f120006, origin='synthetic decoder')
    info, findings, diagnostics = analyze_network_config(apk, {'target_sdk': 28,
        'application': {'networkSecurityConfig': reference}}, Cancellation(), resolve)
    assert calls == [reference]
    assert info['status'] == 'PARSED_DEFAULT_CONFIG' and info['configuration'] == 'default-only'
    assert findings[0].type == 'REVIEW' and diagnostics


@pytest.mark.parametrize('failure', ['wrong-root', 'invalid-path', 'decoder-failure', 'cancel'])
def test_decoder_failure_never_becomes_safe(tmp_path, failure):
    def resolve(*args):
        if failure == 'cancel':
            raise Cancelled()
        if failure == 'decoder-failure':
            raise RuntimeError('Unavailable')
        return dict(xml='<paths/>' if failure == 'wrong-root' else '<network-security-config/>',
                    resource='../bad.xml' if failure == 'invalid-path' else 'res/xml/network.xml')
    args = (tmp_path / 'unused', {'application': {'networkSecurityConfig': '@0x7f120006'}}, Cancellation(), resolve)
    if failure == 'cancel':
        with pytest.raises(Cancelled):
            analyze_network_config(*args)
    else:
        info, _, diagnostics = analyze_network_config(*args)
        assert info['status'] == 'UNKNOWN' and diagnostics
        assert 'base_cleartext_permitted' not in info


def test_qualified_resource_does_not_bypass_local_rejection(tmp_path):
    apk = tmp_path / 'variant.apk'
    with ZipFile(apk, 'w') as z:
        for path in ('res/xml/network.xml', 'res/xml-v28/network.xml'):
            z.writestr(path, b'\x03\x00binary')
    info, _, _ = analyze_network_config(apk, {'application': {'networkSecurityConfig': '@xml/network'}},
        Cancellation(), lambda *args: pytest.fail('Must not bypass qualifier rejection'))
    assert info['status'] == 'UNKNOWN'


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_live_named_and_numeric_compiled_xml_match():
    from analyzer.backends.jeb.backend import JebBackend, file_hash
    from analyzer.app.settings import Settings
    from analyzer.app.project_manager import write_json
    root = Path(__file__).resolve().parents[1]
    samples = list((root / '.codex-remote-attachments').rglob('2-amospro_dev6.apk'))
    if not samples:
        pytest.skip('Local user sample is unavailable')
    with JebBackend(Settings()) as backend:
        backend.input_path = samples[0]
        backend.input_sha256 = file_hash(samples[0])
        token = Cancellation()
        inventory = backend._run('resources', token, **backend._input_request(token))
        row = next(r for r in inventory['resources'] if r['path'] == 'res/xml/network_security_config.xml')
        named = backend.resolve_network_xml('@xml/network_security_config', token)
        numeric = backend.resolve_network_xml('@0x%08x' % row['id'], token)
        assert named['xml'] == numeric['xml'] and named['resource'] == numeric['resource']
        info, findings, diagnostics = analyze_network_config(samples[0], {'target_sdk': 28,
            'application': {'networkSecurityConfig': '@0x%08x' % row['id']}}, token, backend.resolve_network_xml)
        assert info['status'] == 'PARSED_DEFAULT_CONFIG'
        assert info['base_cleartext_permitted'] is False
        assert len(info['domains']) == 2 and all(d['cleartext_permitted'] for d in info['domains'])
        assert findings and diagnostics
        write_json(root / 'build/compiled-network-validation.json', dict(policy=info,
            diagnostics=diagnostics, resource_id=row['id'], numeric_named_match=True,
            input_sha256=backend.input_sha256, session=backend.session_info))
