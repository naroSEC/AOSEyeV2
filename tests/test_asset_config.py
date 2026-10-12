import json
from zipfile import ZipFile

import pytest

from analyzer.analyzers.asset_config import inspect_config, internal_url, MAX_JSON_BYTES
from analyzer.analyzers.apk import inspect_apk
from analyzer.app.jobs import Cancellation, Cancelled


def config(data):
    return inspect_config(json.dumps(data).encode(), 'assets/config.json', Cancellation())


@pytest.mark.parametrize('text,found,diagnostic', [
    ('AWS_ACCESS_KEY_ID=identifier\nAWS_SECRET_ACCESS_KEY=private-marker', True, False),
    ('export AWS_ACCESS_KEY_ID="identifier"\nexport AWS_SECRET_ACCESS_KEY=private-marker', True, False),
    ('[default]\naws_access_key_id=identifier\naws_secret_access_key=private-marker', True, False),
    ('[a]\naws_access_key_id=identifier\n[b]\naws_secret_access_key=private-marker', False, False),
    ('aws_access_key_id=identifier', False, False),
    ('AWS_ACCESS_KEY_ID=identifier\nAWS_SECRET_ACCESS_KEY=${SECRET}', False, False),
    ('AWS_ACCESS_KEY_ID=x\nAWS_ACCESS_KEY_ID=y\nAWS_SECRET_ACCESS_KEY=private-marker', False, True),
    ('aws_access_key_id=x\nAWS_ACCESS_KEY_ID=y\naws_secret_access_key=private-marker', False, True),
    ('unsupported multi line syntax', False, True),
])
def test_assignment_credentials_are_section_scoped_and_redacted(text, found, diagnostic):
    from analyzer.analyzers.asset_config import inspect_assignment_credentials
    findings, diagnostics = inspect_assignment_credentials(text.encode(), 'assets/config.ini', Cancellation())
    assert bool(findings) == found and bool(diagnostics) == diagnostic
    assert 'private-marker' not in repr((findings, diagnostics))


def test_assignment_apk_pipeline(tmp_path):
    apk = tmp_path / 'config.apk'
    with ZipFile(apk, 'w') as archive:
        archive.writestr('assets/config.ini', '[default]\naws_access_key_id=x\naws_secret_access_key=private-marker')
    _, _, findings, _ = inspect_apk(apk, Cancellation())
    assert any(f.rule_id == 'AOS-ASSET-005' for f in findings)
    assert all('private-marker' not in repr(f) for f in findings)


@pytest.mark.parametrize('host', ['10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '127.0.0.2', 'localhost', 'x.localhost', 'dev.example.com', 'staging-1.example.com'])
def test_internal_urls(host):
    assert internal_url('https://' + host + ':8080/path')


@pytest.mark.parametrize('url', ['https://172.15.0.1', 'https://172.32.0.1', 'https://10.999.1.1',
    'https://192.168.1.999', 'https://device.example.com', 'https://example.com/dev',
    'https://dev@example.com', 'https://169.254.1.1', 'https://[bad', 'https:///dev'])
def test_not_private_or_development_url(url):
    assert not internal_url(url)


@pytest.mark.parametrize('host,expected', [('::1', True), ('fd12:3456::1', True),
    ('fc00::1', True), ('fe80::1', True), ('fe80::1%25eth0', True),
    ('::ffff:192.168.1.1', True), ('::ffff:8.8.8.8', False), ('2001:db8::1', False),
    ('2606:4700:4700::1111', False), ('::', False), ('ff02::1', False)])
def test_ipv6_literal_scope(host, expected):
    assert internal_url('https://[' + host + ']:8443/path') is expected


def test_service_account_redacted_and_manual():
    findings, diagnostics, keys = config(dict(type='service_account', client_email='private-marker-email',
        private_key='-----BEGIN PRIVATE KEY-----\nprivate-marker-material'))
    f, = findings
    assert f.rule_id == 'AOS-ASSET-003' and f.type == 'REVIEW'
    assert f.verification == 'MANUAL_REVIEW' and f.analysis_level == 'L2'
    assert 'private-marker' not in repr(f) and not diagnostics and not keys


@pytest.mark.parametrize('data', [{}, {'type': 'service_account', 'client_email': 'test', 'private_key': 'placeholder'},
    {'aws_access_key_id': 'identifier'}, {'aws_secret_access_key': 'secret'},
    {'apiKey': 'public'}, {'apiKey': 'public', 'projectId': 'project', 'appId': 7}])
def test_incomplete_structures(data):
    assert config(data) == ([], [], set())


@pytest.mark.parametrize('data', [
    {'apiKey': 'public-marker', 'projectId': 'project', 'appId': 'app'},
    {'project_info': {'project_id': 'project'}, 'client': [{'api_key': [{'current_key': 'public-marker'}]}]}])
def test_public_firebase_config(data):
    findings, diagnostics, keys = config(data)
    f, = findings
    assert f.rule_id == 'AOS-ASSET-004' and f.severity == 'INFO'
    assert keys == {'public-marker'} and not diagnostics and 'public-marker' not in repr(f)


@pytest.mark.parametrize('access,secret', [('aws_access_key_id', 'aws_secret_access_key'), ('AccessKeyId', 'SecretAccessKey')])
def test_cloud_pair(access, secret):
    findings, diagnostics, keys = config({access: 'identifier-marker', secret: 'secret-marker'})
    f, = findings
    assert f.rule_id == 'AOS-ASSET-005' and f.severity == 'MEDIUM'
    assert 'marker' not in repr(f) and not diagnostics and not keys


@pytest.mark.parametrize('data', [b'{', b'{"apiKey":"a","apiKey":"b"}', b'\xff', b'{"x":NaN}',
    b'[' * 2000 + b']' * 2000, b' ' * (MAX_JSON_BYTES + 1)],
    ids=['syntax', 'duplicate', 'encoding', 'nonfinite', 'depth', 'size'])
def test_bad_or_oversized_json(data):
    findings, diagnostics, keys = inspect_config(data, 'config.json', Cancellation())
    assert not findings and not keys and diagnostics


def test_cancel():
    cancel = Cancellation()
    cancel.cancel()
    with pytest.raises(Cancelled):
        inspect_config(b'{}', 'config.json', cancel)


def apk_findings(tmp_path, data, filename='assets/config.json'):
    path = tmp_path / 'sample.apk'
    with ZipFile(path, 'w') as archive:
        archive.writestr(filename, data)
    return inspect_apk(path, Cancellation())[2:]


def test_public_api_does_not_exempt_password(tmp_path):
    data = dict(apiKey='public-marker', projectId='project', appId='app', password='private-marker')
    findings, diagnostics = apk_findings(tmp_path, json.dumps(data))
    assignments = [f for f in findings if f.rule_id == 'AOS-SECRET-002']
    assert [f.severity for f in assignments] == ['INFO', 'LOW']
    assert not diagnostics and 'private-marker' not in repr(findings)


@pytest.mark.parametrize('count,truncated', [(20, False), (21, True), (100, True)])
def test_pattern_limit_visible(tmp_path, count, truncated):
    findings, diagnostics = apk_findings(tmp_path, '\n'.join('password=secret-marker' for _ in range(count)), 'assets/test.txt')
    assert len(findings) == 20
    assert bool(diagnostics) == truncated
    assert all('truncated' in d for d in diagnostics)


def test_public_urls_do_not_consume_internal_match_limit(tmp_path):
    text = '\n'.join(['https://example.com'] * 25 + ['https://172.16.1.2'])
    findings, diagnostics = apk_findings(tmp_path, text, 'assets/urls.txt')
    assert len(findings) == 1 and findings[0].rule_id == 'AOS-SECRET-005' and not diagnostics


def test_invalid_json_does_not_disable_text_scanning(tmp_path):
    findings, diagnostics = apk_findings(tmp_path, '{password=secret-marker')
    assert any(f.rule_id == 'AOS-SECRET-002' for f in findings) and diagnostics
