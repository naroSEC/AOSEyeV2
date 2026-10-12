from datetime import datetime, timezone
from zipfile import ZipFile, ZIP_DEFLATED

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from analyzer.analyzers.network_certificates import inspect_certificate_bytes, inspect_trust_resources, LIMIT
from analyzer.analyzers.network_config import analyze_network_config, select_cleartext_policy
from analyzer.analyzers.network_trust import parse_trust
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.core.models import AnalysisResult
from analyzer.app.project_manager import save_project, open_project


@pytest.fixture(scope='module')
def certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'AOSEye fixture only')])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2021, 1, 1, tzinfo=timezone.utc)).sign(key, hashes.SHA256()))


@pytest.mark.parametrize('encoding', [serialization.Encoding.PEM, serialization.Encoding.DER])
def test_parse_expired_certificate_is_format_only(certificate, encoding):
    result = inspect_certificate_bytes(certificate.public_bytes(encoding), Cancellation())
    assert result['status'] == 'X509_PARSED'
    assert result['encoding'] == ('PEM' if encoding == serialization.Encoding.PEM else 'DER')
    assert result['certificate_sha256'] == [certificate.fingerprint(hashes.SHA256()).hex()]


@pytest.mark.parametrize('extension,encoding', [('pem', serialization.Encoding.PEM),
    ('crt', serialization.Encoding.PEM), ('cer', serialization.Encoding.DER), ('der', serialization.Encoding.DER)])
def test_apk_certificate_asset_is_public_information(tmp_path, certificate, extension, encoding):
    from analyzer.analyzers.apk import inspect_apk
    path = tmp_path / 'cert.apk'
    with ZipFile(path, 'w') as archive:
        archive.writestr('assets/public.' + extension, certificate.public_bytes(encoding))
    _, _, findings, diagnostics = inspect_apk(path, Cancellation())
    f, = findings
    assert f.rule_id == 'AOS-ASSET-006' and f.type == 'INFORMATION' and f.severity == 'INFO'
    assert f.validation['certificate_structure'] == 'PARSED' and f.validation['trust_usage'] == 'UNKNOWN'
    assert 'AOSEye fixture only' not in repr(f) and not diagnostics
    result = AnalysisResult('cert.apk', '0' * 64, findings=findings)
    assert AnalysisResult.from_dict(result.to_dict()).findings[0].id == f.id


@pytest.mark.parametrize('content', [b'not a certificate', b'x' * (LIMIT + 1)], ids=['invalid', 'budget'])
def test_apk_bad_certificate_preserves_diagnostic(tmp_path, content):
    from analyzer.analyzers.apk import inspect_apk
    path = tmp_path / 'cert.apk'
    with ZipFile(path, 'w') as archive:
        archive.writestr('assets/public.cer', content)
    _, _, findings, diagnostics = inspect_apk(path, Cancellation())
    assert not findings and any('Certificate asset' in d for d in diagnostics)


def test_mixed_certificate_and_key_does_not_hide_private_key(tmp_path, certificate):
    from analyzer.analyzers.apk import inspect_apk
    path = tmp_path / 'mixed.apk'
    with ZipFile(path, 'w') as archive:
        archive.writestr('assets/mixed.pem', certificate.public_bytes(serialization.Encoding.PEM) +
                         b'-----BEGIN PRIVATE KEY-----\nfixture-placeholder\n-----END PRIVATE KEY-----')
    _, _, findings, diagnostics = inspect_apk(path, Cancellation())
    assert any(f.rule_id == 'AOS-SECRET-001' for f in findings)
    assert not any(f.rule_id == 'AOS-ASSET-006' for f in findings) and diagnostics


def test_pem_bundle_duplicates(certificate):
    data = certificate.public_bytes(serialization.Encoding.PEM)
    result = inspect_certificate_bytes(data + data, Cancellation())
    assert result['certificate_count'] == 2 and result['unique_certificate_count'] == 1


@pytest.mark.parametrize('data', [b'', b'garbage', b'0\x03abc', b'-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----', b'x' * (LIMIT + 1)], ids=['empty', 'garbage', 'bad_der', 'bad_pem', 'large'])
def test_invalid_bytes(data):
    with pytest.raises(ValueError):
        inspect_certificate_bytes(data, Cancellation())


@pytest.mark.parametrize('case', ['trailing_pem', 'leading_pem', 'trailing_der', 'count'])
def test_strict_containers(certificate, case):
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    data = {'trailing_pem': pem + b'garbage', 'leading_pem': b'garbage' + pem,
            'trailing_der': certificate.public_bytes(serialization.Encoding.DER) + b'garbage',
            'count': pem * 65}[case]
    with pytest.raises(ValueError):
        inspect_certificate_bytes(data, Cancellation())


def xml(source='@raw/ca'):
    return f'<network-security-config><base-config><trust-anchors><certificates src="{source}"/></trust-anchors></base-config><domain-config><domain>example.com</domain></domain-config></network-security-config>'


def test_pipeline_and_saved_host_lookup(tmp_path, certificate):
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w') as archive:
        archive.writestr('res/xml/network.xml', xml())
        archive.writestr('res/raw/ca.pem', certificate.public_bytes(serialization.Encoding.PEM))
    policy, findings, _ = analyze_network_config(apk, dict(target_sdk=28,
        application={'networkSecurityConfig': '@xml/network'}), Cancellation())
    assert policy['status'] == 'PARSED'
    assert all(f.type == 'REVIEW' for f in findings)
    saved = tmp_path / 'project.json'
    save_project(saved, AnalysisResult('missing.apk', 'abc', manifest={'network_security_config': policy}))
    loaded = open_project(saved).manifest['network_security_config']
    selected = select_cleartext_policy(loaded, 'example.com')['trust']['anchors'][0]
    assert selected['resource_inspection']['status'] == 'X509_PARSED'
    assert selected['resource_inspection']['mapping'] == 'NAMED_PATH_CANDIDATE'
    assert selected['certificate_contents'] == 'PATH_CANDIDATE_X509_PARSED'


@pytest.mark.parametrize('case', ['missing', 'numeric', 'qualified', 'duplicate', 'extension_collision', 'invalid', 'large', 'ratio'])
def test_unresolved_resource(tmp_path, certificate, case):
    apk = tmp_path / 'fixture.apk'
    data = certificate.public_bytes(serialization.Encoding.PEM)
    with ZipFile(apk, 'w', compression=ZIP_DEFLATED) as archive:
        if case not in ('missing', 'numeric'):
            archive.writestr('res/raw/ca.pem', b'bad' if case == 'invalid' else b'x' * (LIMIT + 1) if case == 'large' else b'x' * LIMIT if case == 'ratio' else data)
        if case == 'qualified':
            archive.writestr('res/raw-v28/ca.pem', data)
        if case == 'duplicate':
            with pytest.warns(UserWarning):
                archive.writestr('res/raw/ca.pem', data)
        if case == 'extension_collision':
            archive.writestr('res/raw/ca.der', data)
    trust = parse_trust(xml('@0x7f010001' if case == 'numeric' else '@raw/ca'), 28, False, Cancellation())
    inspect_trust_resources(apk, trust, Cancellation())
    result = trust['base_anchors'][0]['resource_inspection']
    assert result['status'] == 'UNKNOWN' and result['reason']
    if case in ('large', 'ratio'):
        assert 'budget' in result['reason']


def test_cancel(tmp_path):
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        inspect_certificate_bytes(b'bad', token)
    with pytest.raises(Cancelled):
        inspect_trust_resources(tmp_path / 'missing.apk', {}, token)


def test_mid_read_cancel(tmp_path, certificate):
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w') as archive:
        archive.writestr('res/raw/ca', certificate.public_bytes(serialization.Encoding.PEM))
    trust = parse_trust(xml(), 28, False, Cancellation())
    class Token:
        checks = 0
        def check(self):
            self.checks += 1
            if self.checks == 4:
                raise Cancelled('test')
    with pytest.raises(Cancelled):
        inspect_trust_resources(apk, trust, Token())


def test_source_count_budget(tmp_path):
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w'):
        pass
    trust = parse_trust('<network-security-config><base-config><trust-anchors>' +
        ''.join(f'<certificates src="@raw/ca{i}"/>' for i in range(33)) +
        '</trust-anchors></base-config></network-security-config>', 28, False, Cancellation())
    inspect_trust_resources(apk, trust, Cancellation())
    assert 'count budget' in trust['base_anchors'][-1]['resource_inspection']['reason']


def test_total_read_budget(tmp_path):
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w') as archive:
        for i in range(5):
            archive.writestr(f'res/raw/ca{i}', b'x' * LIMIT)
    trust = parse_trust('<network-security-config><base-config><trust-anchors>' +
        ''.join(f'<certificates src="@raw/ca{i}"/>' for i in range(5)) +
        '</trust-anchors></base-config></network-security-config>', 28, False, Cancellation())
    inspect_trust_resources(apk, trust, Cancellation())
    assert 'read budget' in trust['base_anchors'][-1]['resource_inspection']['reason']
    assert 'sha256' not in trust['base_anchors'][-1]['resource_inspection']


def test_missing_archive_is_local_unknown(tmp_path):
    trust = parse_trust(xml(), 28, False, Cancellation())
    inspect_trust_resources(tmp_path / 'missing.apk', trust, Cancellation())
    assert trust['base_anchors'][0]['resource_inspection']['status'] == 'UNKNOWN'


def test_numeric_ca_pipeline_saved_lookup(tmp_path, certificate):
    apk = tmp_path / 'numeric.apk'
    with ZipFile(apk, 'w') as archive:
        archive.writestr('res/xml/network.xml', xml('@7f010001'))
        archive.writestr('res/obfuscated.bin', certificate.public_bytes(serialization.Encoding.DER))
    calls = []
    def resolve(reference, token):
        calls.append(reference)
        return dict(resource='res/obfuscated.bin', resource_id=0x7f010001,
                    configuration='default-only', origin='synthetic table')
    policy, _, diagnostics = analyze_network_config(apk, dict(target_sdk=28,
        application={'networkSecurityConfig': '@xml/network'}), Cancellation(), ca_resolver=resolve)
    assert calls == ['@7f010001']  # inherited references reuse the same result
    assert diagnostics
    output = tmp_path / 'saved.json'
    save_project(output, AnalysisResult('missing.apk', 'abc', manifest={'network_security_config': policy}))
    loaded = open_project(output).manifest['network_security_config']
    anchor = select_cleartext_policy(loaded, 'example.com')['trust']['anchors'][0]
    assert anchor['certificate_contents'] == 'DEFAULT_RESOURCE_X509_PARSED'
    assert anchor['resource_inspection']['configuration'] == 'default-only'
    assert anchor['resource_inspection']['certificate_count'] == 1


@pytest.mark.parametrize('case', ['enabled', 'disabled', 'failure'])
def test_named_ca_automatic_pipeline(tmp_path, certificate, case):
    apk = tmp_path / 'named.apk'
    with ZipFile(apk, 'w') as archive:
        archive.writestr('res/xml/network.xml', xml('@raw/ca'))
        archive.writestr('res/raw/ca.der', certificate.public_bytes(serialization.Encoding.DER))
        archive.writestr('res/obfuscated.bin', certificate.public_bytes(serialization.Encoding.DER))
    def resolve(reference, token):
        if case == 'disabled':
            return dict(status='NAMED_RESOLUTION_DISABLED')
        if case == 'failure':
            raise ValueError('Configured name resolver failed')
        return dict(resource='res/obfuscated.bin', resource_id=0x7f010001,
                    configuration='default-only', reference=reference, name_origin='synthetic aapt2')
    policy, _, diagnostics = analyze_network_config(apk, dict(target_sdk=28,
        application={'networkSecurityConfig': '@xml/network'}), Cancellation(), ca_resolver=resolve)
    assert policy['status'] == 'PARSED' and diagnostics
    selected = select_cleartext_policy(policy, 'example.com')['trust']['anchors'][0]['resource_inspection']
    if case == 'failure':
        assert selected['status'] == 'UNKNOWN' and 'failed' in selected['reason']
        assert 'sha256' not in selected  # no silent path fallback on a configured failure
    else:
        assert selected['status'] == 'X509_PARSED'
        assert selected['mapping'] == ('RESOURCE_TABLE_DEFAULT' if case == 'enabled' else 'NAMED_PATH_CANDIDATE')
