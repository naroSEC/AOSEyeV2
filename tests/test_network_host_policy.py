from copy import deepcopy

import pytest

from analyzer.analyzers.network_config import parse_cleartext, select_cleartext_policy
from analyzer.app.jobs import Cancellation


@pytest.fixture
def policy():
    value = parse_cleartext(b'''<network-security-config><base-config cleartextTrafficPermitted="false"/>
      <domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="true">example.com</domain>
        <domain-config cleartextTrafficPermitted="false"><domain includeSubdomains="true">secure.example.com</domain>
          <domain-config cleartextTrafficPermitted="true"><domain>test.secure.example.com</domain></domain-config>
        </domain-config>
      </domain-config></network-security-config>''', 28, Cancellation())
    return dict(value, status='PARSED_DEFAULT_CONFIG', configuration='default-only')


@pytest.mark.parametrize('host, expected, match', [
    ('example.com', True, 'EXACT'), ('www.example.com', True, 'SUBDOMAIN'),
    ('secure.example.com', False, 'EXACT'), ('a.secure.example.com', False, 'SUBDOMAIN'),
    ('test.secure.example.com', True, 'EXACT'), ('a.test.secure.example.com', False, 'SUBDOMAIN'),
    ('badexample.com', False, 'BASE'), ('example.com.evil.test', False, 'BASE'),
    ('EXAMPLE.COM', True, 'EXACT'), ('unrelated.test', False, 'BASE')])
def test_longest_match_and_label_boundaries(policy, host, expected, match):
    before = deepcopy(policy)
    result = select_cleartext_policy(policy, host)
    assert result['cleartext_permitted'] is expected and result['match'] == match
    assert result['configuration'] == 'default-only' and result['limitation']
    assert policy == before


@pytest.mark.parametrize('host', ['https://example.com', 'example.com:80', '*.example.com',
    'example.com.', ' example.com', 'a..example.com', '-bad.example.com', '127.0.0.1',
    '::1', '한글.example', 'xn--test.example', '', None])
def test_unsupported_host_is_unknown(policy, host):
    assert select_cleartext_policy(policy, host)['status'] == 'UNKNOWN'


@pytest.mark.parametrize('case', ['unresolved', 'absent', 'unknown-value', 'duplicate', 'malformed'])
def test_uncertain_policy_never_falls_back_to_safe(policy, case):
    if case == 'unresolved':
        policy['status'] = 'UNKNOWN'
    elif case == 'absent':
        policy = {}
    elif case == 'unknown-value':
        policy['domains'][0]['cleartext_permitted'] = None
    elif case == 'duplicate':
        policy['domains'].append(dict(policy['domains'][0]))
    else:
        policy['domains'][0]['include_subdomains'] = 'false'
    result = select_cleartext_policy(policy, 'example.com')
    assert result['status'] == 'UNKNOWN' and result['cleartext_permitted'] is None
