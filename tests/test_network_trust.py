from zipfile import ZipFile

import pytest

from analyzer.analyzers.network_trust import parse_trust, select_trust_inventory
from analyzer.analyzers.network_config import analyze_network_config, select_cleartext_policy
from analyzer.app.jobs import Cancellation, Cancelled


@pytest.mark.parametrize('sdk, sources', [(23, ['system', 'user']), (24, ['system']), (None, None)])
def test_defaults(sdk, sources):
    trust = parse_trust('<network-security-config/>', sdk, False, Cancellation())
    assert (None if trust['base_anchors'] is None else [a['source'] for a in trust['base_anchors']]) == sources


@pytest.mark.parametrize('debug, expected', [(True, ['system', 'user']), (False, ['system']), (None, None)])
def test_debug_addition_is_conditional(debug, expected):
    trust = parse_trust('''<network-security-config><debug-overrides><trust-anchors>
        <certificates src="user"/></trust-anchors></debug-overrides></network-security-config>''',
        28, debug, Cancellation())
    assert trust['debug_overrides']['anchors'][0]['override_pins'] is True
    selected = select_trust_inventory(trust, None)['combined_sources']
    assert (None if selected is None else [a['source'] for a in selected]) == expected


def test_inheritance_replaces_parent_and_empty_is_not_default():
    trust = parse_trust('''<network-security-config><base-config><trust-anchors><certificates src="user"/></trust-anchors></base-config>
      <domain-config><domain>a.test</domain><trust-anchors><certificates src="@raw/ca" overridePins="false"/></trust-anchors>
        <domain-config><domain>b.a.test</domain></domain-config>
        <domain-config><domain>c.a.test</domain><trust-anchors/></domain-config>
      </domain-config></network-security-config>''', 28, False, Cancellation())
    assert [a['source'] for a in trust['domains'][0]['anchors']] == ['@raw/ca']
    assert trust['domains'][1]['anchors'] == trust['domains'][0]['anchors']
    assert trust['domains'][2]['anchors'] == []
    assert trust['diagnostics']


@pytest.mark.parametrize('source', ['@raw/ca', '@0x7f010001', 'unknown'])
def test_unknown_certificate_contents_remain_explicit(source):
    trust = parse_trust(f'<network-security-config><base-config><trust-anchors><certificates src="{source}" overridePins="@bool/flag"/></trust-anchors></base-config></network-security-config>', 28, False, Cancellation())
    anchor = trust['base_anchors'][0]
    assert anchor['override_pins'] is None and anchor['certificate_contents'] == 'NOT_INSPECTED'
    assert trust['diagnostics']


@pytest.mark.parametrize('debug, review', [('true', True), ('false', False), ('@bool/debug', True)])
def test_pipeline_host_lookup_and_review(tmp_path, debug, review):
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w') as z:
        z.writestr('res/xml/network.xml', '<network-security-config><debug-overrides><trust-anchors><certificates src="user" overridePins="false"/></trust-anchors></debug-overrides></network-security-config>')
    policy, findings, _ = analyze_network_config(apk, dict(target_sdk=28,
        application={'networkSecurityConfig': '@xml/network', 'debuggable': debug}), Cancellation())
    assert any(f.rule_id == 'AOS-NETWORK-CONFIG-003' for f in findings) is review
    assert all(f.type == 'REVIEW' for f in findings)
    selected = select_cleartext_policy(policy, 'example.com')
    assert selected['trust']['debug_overrides']['anchors'][0]['override_pins'] is False


def test_invalid_trust_does_not_leave_policy_marked_parsed(tmp_path):
    apk = tmp_path / 'invalid.apk'
    with ZipFile(apk, 'w') as z:
        z.writestr('res/xml/network.xml', '<network-security-config><base-config><trust-anchors/><trust-anchors/></base-config></network-security-config>')
    policy, _, diagnostics = analyze_network_config(apk, {'application': {'networkSecurityConfig': '@xml/network'}}, Cancellation())
    assert policy['status'] == 'UNKNOWN' and diagnostics


def test_trust_cancel():
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        parse_trust('<network-security-config><domain-config><domain>a.test</domain></domain-config></network-security-config>', 28, False, token)
