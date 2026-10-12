import base64
from datetime import date
from zipfile import ZipFile

import pytest

from analyzer.analyzers.network_pins import parse_pins, select_pin_inventory
from analyzer.analyzers.network_config import analyze_network_config, select_cleartext_policy
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.project_manager import save_project, open_project
from analyzer.core.models import AnalysisResult

PIN = base64.b64encode(b'x' * 32).decode()


def xml(expiration='', algorithm='SHA-256', value=PIN):
    return f'<network-security-config><domain-config><domain>example.com</domain><pin-set {expiration}><pin digest="{algorithm}">{value}</pin></pin-set></domain-config></network-security-config>'


@pytest.mark.parametrize('expiration, status', [('', 'NO_EXPIRATION'),
    ('2026-10-02', 'PAST_EXPIRATION_DATE'), ('2026-10-04', 'BEFORE_EXPIRATION_DATE'),
    ('2026-10-03', 'EXPIRATION_DAY_UNCERTAIN'), ('2026-02-30', 'UNKNOWN'),
    ('@string/date', 'UNKNOWN'), ('20261003', 'UNKNOWN')])
def test_date_is_explicit_and_boundary_conservative(expiration, status):
    value = parse_pins(xml(f'expiration="{expiration}"' if expiration else ''), Cancellation(), date(2026, 10, 3))
    assert value['as_of_date'] == '2026-10-03'
    assert value['declarations'][0]['expiration_state'] == status


@pytest.mark.parametrize('algorithm, value, valid', [('SHA-256', PIN, True), ('sha-256', PIN, False),
    ('SHA-1', PIN, False), ('SHA-256', '%%%%', False), ('SHA-256', base64.b64encode(b'x').decode(), False),
    ('SHA-256', '@string/pin', False)])
def test_pin_validation(algorithm, value, valid):
    pinset = parse_pins(xml(algorithm=algorithm, value=value), Cancellation())['declarations'][0]
    assert pinset['valid_unique_pin_count'] == int(valid)
    assert pinset['certificate_match'] == 'NOT_VERIFIED'


def test_inheritance_empty_override_and_duplicates():
    data = f'''<network-security-config><domain-config><domain>a.test</domain>
      <pin-set><pin digest="SHA-256">{PIN}</pin><pin digest="SHA-256">{PIN}</pin></pin-set>
      <domain-config><domain>b.a.test</domain></domain-config>
      <domain-config><domain>c.a.test</domain><pin-set/></domain-config>
      </domain-config></network-security-config>'''
    result = parse_pins(data, Cancellation())
    assert result['declarations'][0]['valid_unique_pin_count'] == 1
    assert result['domains'][0]['pin_set'] == result['domains'][1]['pin_set']
    assert select_pin_inventory(result, 'c.a.test')['pin_set']['empty']
    assert select_pin_inventory(result, None)['status'] == 'NO_SELECTED_DECLARATION'


def test_saved_host_result_keeps_analysis_date(tmp_path):
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w') as z:
        z.writestr('res/xml/network.xml', xml('expiration="2000-01-01"'))
    policy, findings, _ = analyze_network_config(apk, dict(target_sdk=28,
        application={'networkSecurityConfig': '@xml/network'}), Cancellation())
    assert any(f.rule_id == 'AOS-NETWORK-CONFIG-004' and f.type == 'REVIEW' for f in findings)
    result = AnalysisResult('missing.apk', 'abc', manifest={'network_security_config': policy})
    output = tmp_path / 'saved.json'
    save_project(output, result)
    loaded = open_project(output).manifest['network_security_config']
    selected = select_cleartext_policy(loaded, 'example.com')['pinning']
    assert selected['as_of_date'] == policy['pinning']['as_of_date']
    assert selected['pin_set']['expiration_state'] == 'PAST_EXPIRATION_DATE'


def test_pin_cancel():
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        parse_pins(xml(), token)


@pytest.mark.parametrize('data', ['<network-security-config><base-config><pin-set/></base-config></network-security-config>',
    '<network-security-config><domain-config><domain>a.test</domain><pin-set/><pin-set/></domain-config></network-security-config>'])
def test_invalid_structure(data):
    with pytest.raises(ValueError):
        parse_pins(data, Cancellation())
