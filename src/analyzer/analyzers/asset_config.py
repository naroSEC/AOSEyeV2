"""Bounded JSON configuration classification; no credential validation or network I/O."""
import json
import re
from ipaddress import ip_address, IPv4Network, IPv6Network
from urllib.parse import urlsplit

from analyzer.core.models import Finding, Location

MAX_JSON_BYTES = 256 * 1024
PRIVATE_NETWORKS = tuple(IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'))
LOCAL_V6 = tuple(IPv6Network(n) for n in ('fc00::/7', 'fe80::/10', '::1/128'))


def internal_url(value):
    try:
        host = urlsplit(value).hostname
        if not host:
            return False
        if host == 'localhost' or host.endswith('.localhost'):
            return True
        try:
            address = ip_address(host)
        except ValueError:
            # Do not classify "device" or a username/query containing "dev".
            return any(re.fullmatch(r'(?:dev|staging)(?:[-\d].*)?', label) for label in host.split('.'))
        if address.version == 6:
            mapped = address.ipv4_mapped
            return (any(mapped in network for network in PRIVATE_NETWORKS) if mapped else
                    any(address in network for network in LOCAL_V6))
        return any(address in network for network in PRIVATE_NETWORKS)
    except ValueError:
        return False


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def inspect_assignment_credentials(content, filename, cancel):
    """Strict flat dotenv/properties or INI sections; never evaluate interpolation."""
    cancel.check()
    if len(content) > MAX_JSON_BYTES:
        return [], ['Assignment configuration byte budget exceeded: ' + filename]
    try:
        text = content.decode('utf-8-sig')
        sections, current = {'': {}}, ''
        aliases = {'aws_access_key_id': 'access', 'AWS_ACCESS_KEY_ID': 'access',
                   'aws_secret_access_key': 'secret', 'AWS_SECRET_ACCESS_KEY': 'secret'}
        count = 0
        for line in text.splitlines():
            cancel.check()
            line = line.strip()
            if not line or line.startswith(('#', ';', '!')):
                continue
            if line.startswith('[') and line.endswith(']'):
                current = line[1:-1].strip()
                if not current or current in sections or len(sections) >= 64:
                    raise ValueError('duplicate/invalid section')
                sections[current] = {}
                continue
            if line.startswith('export '):
                line = line[7:].lstrip()
            match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*)', line)
            if not match or '\\' in line:
                raise ValueError('unsupported syntax')
            key, value = match.groups()
            count += 1
            if count > 4096 or key in sections[current]:
                raise ValueError('duplicate key or key budget')
            if value.startswith(('"', "'")):
                if len(value) < 2 or value[-1] != value[0]:
                    raise ValueError('unsupported quoting')
                value = value[1:-1]
            # Keep values local, never expand variables, execute, or include them in diagnostics.
            sections[current][key] = value
        pairs = 0
        for values in sections.values():
            selected = {}
            for key, value in values.items():
                if key in aliases and value.strip() and '$' not in value and '`' not in value:
                    canonical = aliases[key]
                    if canonical in selected:
                        raise ValueError('ambiguous credential key aliases')
                    selected[canonical] = value
            pairs += set(selected) == {'access', 'secret'}
    except (ValueError, UnicodeError):
        return [], ['Assignment configuration invalid, unsupported or over budget: ' + filename]
    if not pairs:
        return [], []
    return [Finding('AOS-ASSET-005', 'Bundled AWS credential pair candidate',
        'Paired AWS identifier and secret assignment fields occur in the same configuration section. '
        'Values may be placeholders; validity, privileges and runtime use remain unknown.',
        'SECRETS', severity='MEDIUM', confidence='HIGH', analysis_level='L2', location=Location(file=filename),
        evidence=['Recognized assignment sections with credential pairs: ' + str(pairs) + '; all values redacted.'],
        recommendation='Review runtime use and restrictions; rotate only confirmed exposed credentials.')], []


def _check_depth(text, cancel):
    depth, quoted, escaped = 0, False, False
    for index, char in enumerate(text):
        if index % 4096 == 0:
            cancel.check()
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '{[':
            depth += 1
            if depth > 32:
                raise ValueError('depth budget')
        elif char in '}]':
            depth -= 1


def inspect_config(content, filename, cancel):
    """Return findings, diagnostics, and public-config API values (memory only)."""
    cancel.check()
    if len(content) > MAX_JSON_BYTES:
        return [], ['JSON configuration byte budget exceeded: ' + filename], set()
    try:
        text = content.decode('utf-8-sig')
        _check_depth(text, cancel)
        data = json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite')))
    except (ValueError, UnicodeError, RecursionError):
        return [], ['JSON configuration invalid or unsupported: ' + filename], set()
    cancel.check()
    if not isinstance(data, dict):
        return [], [], set()
    findings, public_keys = [], set()

    def populated(obj, key):
        return isinstance(obj.get(key), str) and bool(obj[key].strip())

    def add(rule, title, description, severity):
        findings.append(Finding(rule, title, description, 'SECRETS', severity=severity,
            confidence='HIGH', analysis_level='L2', location=Location(file=filename),
            evidence=['Recognized JSON field structure; all values redacted.'],
            recommendation='Review runtime use and restrictions; rotate only confirmed exposed credentials.'))

    if data.get('type') == 'service_account' and populated(data, 'client_email') and populated(data, 'private_key'):
        if re.search(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', data['private_key']):
            add('AOS-ASSET-003', 'Bundled service-account private key candidate',
                'Service-account fields contain a private-key PEM marker. Key validity, account privileges '
                'and runtime use are not established.', 'MEDIUM')

    if all(populated(data, key) for key in ('apiKey', 'projectId', 'appId')):
        public_keys.add(data['apiKey'])
    project = data.get('project_info')
    clients = data.get('client')
    if isinstance(project, dict) and populated(project, 'project_id') and isinstance(clients, list):
        for client in clients:
            cancel.check()
            if not isinstance(client, dict) or not isinstance(client.get('api_key'), list):
                continue
            for key in client['api_key']:
                if isinstance(key, dict) and populated(key, 'current_key'):
                    public_keys.add(key['current_key'])
    if public_keys:
        add('AOS-ASSET-004', 'Firebase client configuration candidate',
            'Firebase-style client configuration is normally public, not proof of a secret leak. '
            'Service restrictions, Security Rules and App Check require separate review; '
            'other credentials in this file are not exempt.', 'INFO')

    # Exact paired fields only: an access-key identifier alone is not a secret.
    for access, secret in (('aws_access_key_id', 'aws_secret_access_key'), ('AccessKeyId', 'SecretAccessKey')):
        if populated(data, access) and populated(data, secret):
            add('AOS-ASSET-005', 'Bundled AWS credential pair candidate',
                'Paired access-key identifier and secret-access-key fields are populated. '
                'These may be placeholders; validity, privileges and runtime use are not established.', 'MEDIUM')
            break
    return findings, [], public_keys
