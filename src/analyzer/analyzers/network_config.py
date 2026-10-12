"""Bounded cleartext policy inventory, not TLS or runtime enforcement proof."""
import re
import ipaddress
from zipfile import ZipFile

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from analyzer.app.jobs import Cancelled
from analyzer.core.models import Finding, Location
from analyzer.analyzers.network_trust import parse_trust, select_trust_inventory
from analyzer.analyzers.network_pins import parse_pins, select_pin_inventory
from analyzer.analyzers.network_certificates import inspect_trust_resources


def select_cleartext_policy(policy, host):
    """Select a rule in the supplied configuration, never prove runtime safety.

    Accept bare ASCII DNS names only. Do not guess URL, IDNA or IP semantics.
    """
    result = dict(host=host, status='UNKNOWN', cleartext_permitted=None,
                  matched_domain=None, match='NONE', configuration=policy.get('configuration', 'supplied'),
                  scope='Supplied NSC configuration only; not runtime enforcement or TLS safety')
    def valid_name(value):
        if not isinstance(value, str) or not value.isascii() or len(value) > 253:
            return False
        labels = value.lower().split('.')
        if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
               or label.startswith('xn--') for label in labels):
            return False
        try:
            ipaddress.ip_address(value)
            return False
        except ValueError:
            return True
    if not valid_name(host):
        return dict(result, reason='Provide a bare ASCII DNS host; URL, port, IP, IDN and trailing dot are unsupported')
    result['host'] = host = host.lower()
    if policy.get('status') not in ('PARSED', 'PARSED_DEFAULT_CONFIG'):
        return dict(result, reason='Network security configuration is unresolved or absent')
    rows = policy.get('domains')
    if not isinstance(rows, list) or len(rows) > 2000:
        return dict(result, reason='Invalid domain inventory or budget exceeded')
    matches, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or not valid_name(row.get('domain')):
            return dict(result, reason='Unsupported domain in policy inventory')
        name = row['domain'].lower()
        value = row.get('cleartext_permitted')
        if name in seen or type(row.get('include_subdomains')) is not bool or (value is not None and type(value) is not bool):
            return dict(result, reason='Duplicate or malformed domain policy')
        seen.add(name)
        if host == name or (row['include_subdomains'] and host.endswith('.' + name)):
            matches.append(row)
    if matches:
        selected = max(matches, key=lambda row: len(row['domain']))
        value = selected.get('cleartext_permitted')
        result.update(matched_domain=selected['domain'].lower(),
                      match='EXACT' if host == selected['domain'].lower() else 'SUBDOMAIN')
    else:
        value = policy.get('base_cleartext_permitted')
        result['match'] = 'BASE'
    if isinstance(policy.get('trust'), dict):
        result['trust'] = select_trust_inventory(policy['trust'], result['matched_domain'])
    if isinstance(policy.get('pinning'), dict):
        result['pinning'] = select_pin_inventory(policy['pinning'], result['matched_domain'])
    if type(value) is not bool:
        return dict(result, reason='Selected cleartext value is unresolved')
    result.update(status='PERMITTED' if value else 'NOT_PERMITTED', cleartext_permitted=value)
    if policy['status'] == 'PARSED_DEFAULT_CONFIG':
        result['configuration'] = 'default-only'
        result['limitation'] = 'Device-specific alternatives are not evaluated'
    return result


def parse_cleartext(data, target_sdk, cancel):
    root = ET.fromstring(data)
    if root.tag != 'network-security-config':
        raise ValueError('Unexpected network security XML root')
    nodes = list(root.iter())
    if len(nodes) > 2000:
        raise ValueError('Network security XML node budget exceeded')
    def boolean(node, key, default):
        raw = node.get(key)
        if raw is None:
            return default
        if raw not in ('true', 'false'):
            raise ValueError('Unresolved or invalid ' + key)
        return raw == 'true'
    base_nodes = root.findall('base-config')
    if len(base_nodes) > 1:
        raise ValueError('Multiple base-config elements')
    default = target_sdk < 28 if type(target_sdk) is int else None
    base = boolean(base_nodes[0], 'cleartextTrafficPermitted', default) if base_nodes else default
    domains, seen = [], set()
    def visit(node, inherited, depth):
        cancel.check()
        if depth > 32:
            raise ValueError('Network security XML depth budget exceeded')
        value = boolean(node, 'cleartextTrafficPermitted', inherited)
        entries = node.findall('domain')
        if not entries:
            raise ValueError('domain-config has no domain')
        for entry in entries:
            name = (entry.text or '').strip().lower()
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', name) or '..' in name:
                raise ValueError('Unsupported or invalid domain')
            if name in seen:
                raise ValueError('Duplicate network security domain')
            seen.add(name)
            domains.append(dict(domain=name, include_subdomains=boolean(entry, 'includeSubdomains', False),
                                cleartext_permitted=value, depth=depth))
        for child in node.findall('domain-config'):
            visit(child, value, depth + 1)
    for node in root.findall('domain-config'):
        visit(node, base, 1)
    return dict(base_cleartext_permitted=base, domains=domains,
                scope='Cleartext inheritance inventory for NSC-capable Android (API 24+); '
                      'not host resolution, TLS validation, trust/pinning, or runtime enforcement proof')


def _policy_result(info, data, resource, manifest, cancel, default_only=False, apk_path=None, ca_resolver=None):
    cleartext = parse_cleartext(data, manifest.get('target_sdk'), cancel)
    debug = manifest.get('application', {}).get('debuggable', 'false')
    debug = True if debug == 'true' else False if debug == 'false' else None
    trust = parse_trust(data, manifest.get('target_sdk'), debug, cancel)
    pinning = parse_pins(data, cancel)
    if apk_path is not None:
        inspect_trust_resources(apk_path, trust, cancel, ca_resolver)
    info.update(cleartext, resource=resource, status='PARSED_DEFAULT_CONFIG' if default_only else 'PARSED',
                scope='Cleartext and declared trust-source inventory in supplied NSC configuration; '
                      'not certificate validation, full pin-set analysis or runtime enforcement proof')
    info['trust'] = trust
    info['pinning'] = pinning
    findings = []
    if info['base_cleartext_permitted'] is True or any(d['cleartext_permitted'] is True for d in info['domains']):
        findings.append(Finding('AOS-NETWORK-CONFIG-001', 'Cleartext permitted by network configuration',
            'Configuration inventory only; domain exceptions and OS/network stack support affect behavior. '
            'This is not evidence that sensitive data is transmitted.', 'NETWORK', type='REVIEW',
            analysis_level='L0', confidence='HIGH', location=Location(file=resource), evidence=[str(info)]))
    diagnostics = ['Network security configuration: only default resource configuration decoded; '
                   'device-specific alternatives are not evaluated'] if default_only else []
    diagnostics.extend('Network trust: ' + message for message in trust['diagnostics'])
    diagnostics.extend('Network pins: ' + message for message in pinning['diagnostics'])
    if any(p['expiration_state'] in ('PAST_EXPIRATION_DATE', 'EXPIRATION_DAY_UNCERTAIN', 'UNKNOWN')
           or p['empty'] or p['valid_unique_pin_count'] < p['declared_pin_count']
           for p in pinning['declarations']):
        findings.append(Finding('AOS-NETWORK-CONFIG-004', 'Pin-set declaration requires review',
            'Review expiration, empty/duplicate or unresolved pin declarations. Saved date-based analysis '
            'does not prove runtime TLS enforcement or bypass.', 'NETWORK', type='REVIEW',
            analysis_level='L0', confidence='MEDIUM', location=Location(file=resource), evidence=[str(pinning)]))
    sources = list(trust['base_anchors'] or [])
    for row in trust['domains']:
        sources.extend(row['anchors'] or [])
    if trust['debug_overrides']['active'] is not False:
        sources.extend(trust['debug_overrides']['anchors'])
    if any(a['origin'] == 'EXPLICIT' and (a['kind'] != 'SYSTEM' or a['override_pins'] is not False) for a in sources):
        findings.append(Finding('AOS-NETWORK-CONFIG-003', 'Trust anchor configuration requires review',
            'Declared trust sources or conditional pin overrides warrant review; CA contents and runtime '
            'TLS behavior are not verified. This is not a confirmed vulnerability.', 'NETWORK', type='REVIEW',
            analysis_level='L0', confidence='MEDIUM', location=Location(file=resource), evidence=[str(trust)]))
    return info, findings, diagnostics


def analyze_network_config(path, manifest, cancel, resolver=None, ca_resolver=None):
    reference = manifest.get('application', {}).get('networkSecurityConfig')
    if reference is None:
        return None, [], []
    info = dict(reference=reference, status='UNKNOWN', scope='Cleartext policy only')
    try:
        cancel.check()
        match = re.fullmatch(r'@xml/([a-zA-Z0-9_]+)', reference)
        if not match:
            raise ValueError('Numeric, aliased or qualified resource reference is not resolved')
        name = match.group(1) + '.xml'
        expected = 'res/xml/' + name
        with ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 100000:
                raise ValueError('ZIP entry budget exceeded')
            candidates = [e for e in entries if re.fullmatch(r'res/xml(?:-[^/]+)?/' + re.escape(name), e.filename)]
            if len(candidates) != 1 or candidates[0].filename != expected:
                raise ValueError('Missing, duplicate or configuration-qualified XML resource')
            entry = candidates[0]
            if entry.file_size > 1024 * 1024 or entry.file_size / max(1, entry.compress_size) > 1000:
                raise ValueError('Network security XML read budget exceeded')
            with archive.open(entry) as stream:
                data = stream.read(1024 * 1024 + 1)
            cancel.check()
            if len(data) > 1024 * 1024:
                raise ValueError('Network security XML read budget exceeded')
            if not data.lstrip().startswith(b'<'):
                raise ValueError('Compiled/binary XML resource decoding is not implemented')
        return _policy_result(info, data, expected, manifest, cancel, apk_path=path, ca_resolver=ca_resolver)
    except Cancelled:
        raise
    except (OSError, ValueError, RuntimeError, ET.ParseError, DefusedXmlException) as exc:
        # Do not bypass duplicate/configuration/read-budget rejection via a decoder.
        if resolver is not None and (re.fullmatch(r'@(?:0x)?[0-9a-fA-F]{8}', reference)
                                     or str(exc) == 'Compiled/binary XML resource decoding is not implemented'):
            try:
                decoded = resolver(reference, cancel)
                cancel.check()
                text, resource = decoded['xml'], decoded['resource']
                if not isinstance(text, str) or len(text.encode('utf-8')) > 1024 * 1024:
                    raise ValueError('Decoded XML text budget/type invalid')
                if not isinstance(resource, str) or not resource.startswith('res/') or '..' in resource.split('/'):
                    raise ValueError('Invalid decoded resource path')
                resolved = dict(info, origin=decoded.get('origin', 'JEB XML decoder'),
                                resource_id=decoded.get('resource_id'), configuration='default-only')
                return _policy_result(resolved, text, resource, manifest, cancel, default_only=True, apk_path=path, ca_resolver=ca_resolver)
            except Cancelled:
                raise
            except (OSError, ValueError, RuntimeError, KeyError, TypeError, ET.ParseError, DefusedXmlException) as decode_error:
                exc = decode_error
        info['reason'] = str(exc)
        message = 'Network security configuration unresolved: ' + str(exc)
        return info, [Finding('AOS-NETWORK-CONFIG-002', 'Unresolved network security configuration',
            message, 'NETWORK', type='REVIEW', confidence='LOW', analysis_level='L0',
            location=Location(file='AndroidManifest.xml'), evidence=[str(reference)])], [message]
