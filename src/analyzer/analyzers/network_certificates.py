"""Bounded APK raw-resource inventory, not Android resource or TLS validation."""
import hashlib
import re
from zipfile import BadZipFile, ZipFile

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization

LIMIT = 1024 * 1024
SCOPE = ('Named res/raw path candidates only; resource-table aliases, numeric IDs and device '
         'configurations are not resolved. X.509 parsing does not validate CA suitability, '
         'signatures, validity, chains, pin matches or runtime TLS behavior.')


def inspect_certificate_bytes(data, cancel):
    cancel.check()
    if not data or len(data) > LIMIT:
        raise ValueError('Certificate resource empty or read budget exceeded')
    if data.lstrip().startswith(b'-----BEGIN CERTIFICATE-----'):
        blocks = list(re.finditer(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----', data))
        if not blocks or len(blocks) > 64:
            raise ValueError('PEM certificate count/format unsupported')
        end = 0
        certs = []
        for block in blocks:
            cancel.check()
            if data[end:block.start()].strip():
                raise ValueError('Non-certificate PEM content unsupported')
            certs.append(x509.load_pem_x509_certificate(block.group()))
            end = block.end()
        if data[end:].strip():
            raise ValueError('Trailing PEM content unsupported')
        encoding = 'PEM'
    else:
        certs = [x509.load_der_x509_certificate(data)]
        if certs[0].public_bytes(serialization.Encoding.DER) != data:
            raise ValueError('Non-canonical or trailing DER content unsupported')
        encoding = 'DER'
    fingerprints = []
    for cert in certs:
        cancel.check()
        fingerprints.append(cert.fingerprint(hashes.SHA256()).hex())
    return dict(status='X509_PARSED', encoding=encoding, certificate_count=len(certs),
                unique_certificate_count=len(set(fingerprints)), certificate_sha256=fingerprints)


def select_raw_resource(inventory, reference):
    match = re.fullmatch(r'@(?:0x)?([0-9a-fA-F]{8})', reference)
    if not match or inventory.get('configuration') != 'default':
        raise ValueError('Unsupported CA reference or resource configuration')
    rows = inventory.get('resources')
    if not isinstance(rows, list) or len(rows) > 4096:
        raise ValueError('Invalid raw resource inventory or budget exceeded')
    resource_id = int(match.group(1), 16)
    if any(not isinstance(row, dict) or type(row.get('id')) is not int for row in rows):
        raise ValueError('Malformed raw resource inventory')
    matches = [row for row in rows if row['id'] & 0xffffffff == resource_id]
    if len(matches) != 1 or matches[0].get('type') != 3:
        raise ValueError('Raw resource ID missing, aliased, complex or ambiguous')
    path = matches[0].get('path')
    if not valid_resource_path(path):
        raise ValueError('Invalid raw resource path')
    return dict(resource=path, resource_id=resource_id, configuration='default-only',
                origin='JEB raw resource table')


def valid_resource_path(path):
    return (isinstance(path, str) and path.startswith('res/') and len(path) <= 1024
            and not any(c in path for c in ('\\', ':', '\x00'))
            and all(part not in ('', '.', '..') for part in path.split('/')))


def inspect_trust_resources(path, trust, cancel, resolver=None):
    """Attach one cached inspection per source; preserve unresolved declarations."""
    cancel.check()
    anchors = list(trust['base_anchors'] or [])
    for row in trust['domains']:
        anchors.extend(row['anchors'] or [])
    anchors.extend(trust['debug_overrides']['anchors'])
    sources = list(dict.fromkeys(a['source'] for a in anchors if a['kind'] == 'RESOURCE'))
    if not sources:
        return
    results = {}
    remaining = 4 * LIMIT
    try:
        with ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 100000:
                raise ValueError('ZIP entry budget exceeded')
            # Index once to avoid a scan for every declared source.
            index = {}
            for entry in entries:
                cancel.check()
                match = re.fullmatch(r'res/raw(?:-[^/]+)?/([A-Za-z0-9_]+)(?:\.[A-Za-z0-9_]+)?', entry.filename)
                if match:
                    index.setdefault(match.group(1), []).append(entry)
            for number, source in enumerate(sources):
                cancel.check()
                result = dict(status='UNKNOWN', scope=SCOPE)
                results[source] = result
                try:
                    if number >= 32:
                        raise ValueError('CA resource count budget exceeded')
                    match = re.fullmatch(r'@raw/([A-Za-z0-9_]+)', source)
                    decoded = resolver(source, cancel) if resolver is not None else None
                    cancel.check()
                    if match and (decoded is None or decoded == dict(status='NAMED_RESOLUTION_DISABLED')):
                        candidates = index.get(match.group(1), [])
                        if len(candidates) != 1 or not candidates[0].filename.startswith('res/raw/'):
                            raise ValueError('Missing, duplicate or configuration-qualified CA path candidate')
                        entry = candidates[0]
                        result.update(resource=entry.filename, mapping='NAMED_PATH_CANDIDATE')
                    else:
                        if decoded is None:
                            raise ValueError('Numeric CA resource ID requires resource-table resolution')
                        if (not isinstance(decoded, dict) or not valid_resource_path(decoded.get('resource'))
                                or decoded.get('configuration') != 'default-only'
                                or type(decoded.get('resource_id')) is not int
                                or (match is not None and decoded.get('reference') != source)
                                or (match is None and decoded['resource_id'] != int(source.removeprefix('@').removeprefix('0x'), 16))):
                            raise ValueError('Invalid decoded CA resource mapping')
                        result.update(decoded, mapping='RESOURCE_TABLE_DEFAULT', status='UNKNOWN',
                            scope='Default raw resource table mapping only; device-specific alternatives, '
                                  'CA suitability, signatures, validity, chains, pins and runtime TLS are not verified.')
                        candidates = [e for e in entries if e.filename == decoded['resource']]
                        if len(candidates) != 1:
                            raise ValueError('Mapped CA resource missing or duplicated in ZIP')
                        entry = candidates[0]
                    if entry.file_size > LIMIT or entry.file_size > remaining or entry.file_size / max(1, entry.compress_size) > 1000:
                        raise ValueError('CA resource read budget exceeded')
                    with archive.open(entry) as stream:
                        data = stream.read(min(LIMIT, remaining) + 1)
                    cancel.check()
                    remaining -= len(data)
                    if remaining < 0:
                        raise ValueError('Total CA resource read budget exceeded')
                    result.update(size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                    result.update(inspect_certificate_bytes(data, cancel))
                except (OSError, ValueError, RuntimeError, BadZipFile, NotImplementedError, UnsupportedAlgorithm) as exc:
                    result['reason'] = str(exc)
    except (OSError, ValueError, RuntimeError, BadZipFile) as exc:
        results = {source: dict(status='UNKNOWN', reason=str(exc), scope=SCOPE) for source in sources}
    for anchor in anchors:
        if anchor['kind'] == 'RESOURCE':
            anchor['resource_inspection'] = results[anchor['source']]
            anchor['certificate_contents'] = (('DEFAULT_RESOURCE_X509_PARSED'
                if results[anchor['source']].get('mapping') == 'RESOURCE_TABLE_DEFAULT' else 'PATH_CANDIDATE_X509_PARSED')
                if results[anchor['source']]['status'] == 'X509_PARSED' else 'UNKNOWN')
    trust['diagnostics'].append('CA format checking uses named path candidates or default-only resource mappings; device selection and TLS validation remain unverified')
