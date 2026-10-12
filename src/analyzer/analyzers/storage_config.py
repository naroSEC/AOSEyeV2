"""Bounded FileProvider/backup declaration review; not runtime access or data-flow proof."""
import re
from zipfile import ZipFile, BadZipFile

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from analyzer.app.jobs import Cancelled
from analyzer.core.models import Finding, Location

MAX_XML = 1024 * 1024


def read_xml(path, reference, cancel, resolver=None, named_resolver=None):
    cancel.check()
    named = re.fullmatch(r'@xml/([A-Za-z0-9_]+)', reference)
    numeric = re.fullmatch(r'@(?:0x)?[0-9a-fA-F]{8}', reference)
    if named:
        name = named[1] + '.xml'
        with ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 100000:
                raise ValueError('XML ZIP entry limit exceeded')
            matches = [e for e in entries if re.fullmatch(r'res/xml(?:-[^/]+)?/' + re.escape(name), e.filename)]
            if not matches and named_resolver is not None:
                # Only absent paths can use resource-table mapping. Never bypass
                # duplicate/qualified entries with a default configuration lookup.
                resolver = named_resolver
            elif len(matches) != 1 or matches[0].filename != 'res/xml/' + name:
                raise ValueError('XML missing, duplicate, or configuration-qualified')
            if matches:
                entry = matches[0]
                if entry.file_size > MAX_XML or entry.file_size / max(1, entry.compress_size) > 1000:
                    raise ValueError('XML read budget exceeded')
                with archive.open(entry) as stream:
                    data = stream.read(MAX_XML + 1)
                cancel.check()
                if len(data) > MAX_XML:
                    raise ValueError('XML read budget exceeded')
                if data.lstrip().startswith(b'<'):
                    return data, entry.filename, 'named-unqualified', {}
    elif not numeric:
        raise ValueError('Unsupported or unresolved XML reference')
    if resolver is None:
        raise ValueError('JEB XML decoder unavailable')
    decoded = resolver(reference, cancel)
    cancel.check()
    text, resource = decoded['xml'], decoded['resource']
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_XML:
        raise ValueError('Decoded XML budget/type invalid')
    if not isinstance(resource, str) or not resource.startswith('res/') or '..' in resource.split('/'):
        raise ValueError('Invalid decoded XML path')
    mapping = {key: decoded[key] for key in ('resource_id', 'name_origin', 'package', 'reference') if key in decoded}
    return text.encode('utf-8'), resource, 'default-only', mapping


def parse_rules(data, kind, cancel):
    cancel.check()
    if kind not in ('fileprovider', 'fullBackupContent', 'dataExtractionRules'):
        raise ValueError('Unsupported storage XML kind')
    if len(data) > MAX_XML:
        raise ValueError('XML size limit exceeded')
    root = ET.fromstring(data)
    if len(list(root.iter())) > 2000:
        raise ValueError('XML node limit exceeded')
    if kind == 'fileprovider':
        if root.tag != 'paths':
            raise ValueError('Expected FileProvider paths root')
        allowed = {'root-path', 'files-path', 'cache-path', 'external-path', 'external-files-path', 'external-cache-path', 'external-media-path'}
        rows, names = [], set()
        for node in root:
            cancel.check()
            if node.tag not in allowed or list(node) or not node.get('name') or node.get('name') in names:
                raise ValueError('Unknown/nested path or missing/duplicate path name')
            names.add(node.get('name'))
            path = node.get('path', '')
            reasons = []
            if node.tag == 'root-path':
                reasons.append('DEVICE_ROOT_BASE')
            if path in ('', '.', './', '/') or path.startswith('/') or '..' in path.split('/'):
                reasons.append('BROAD_OR_PARENT_PATH')
            if node.tag == 'external-path':
                reasons.append('EXTERNAL_STORAGE_BASE')
            rows.append(dict(type=node.tag, name=node.get('name'), path=path, review_reasons=reasons))
        return dict(paths=rows)
    expected = 'full-backup-content' if kind == 'fullBackupContent' else 'data-extraction-rules'
    if root.tag != expected:
        raise ValueError('Unexpected backup XML root')
    groups = [(root.tag, root)] if kind == 'fullBackupContent' else [(node.tag, node) for node in root]
    allowed_groups = ('full-backup-content',) if kind == 'fullBackupContent' else ('cloud-backup', 'device-transfer', 'cross-platform-transfer')
    if any(name not in allowed_groups for name, _ in groups):
        raise ValueError('Unknown backup transport section')
    if len({name for name, _ in groups}) != len(groups):
        raise ValueError('Duplicate backup transport section')
    domains = {'root', 'file', 'database', 'sharedpref', 'external', 'device_root', 'device_file', 'device_database', 'device_sharedpref'}
    result = []
    for name, group in groups:
        rows = []
        for node in group:
            cancel.check()
            if node.tag not in ('include', 'exclude') or list(node) or node.get('domain') not in domains or node.get('path') is None:
                raise ValueError('Unsupported backup rule')
            rows.append(dict(action=node.tag, **node.attrib))
        result.append(dict(transport=name, attributes=dict(group.attrib), rules=rows,
                           selection='explicit-includes' if any(r['action'] == 'include' for r in rows) else 'platform-default-minus-excludes'))
    return dict(transports=result, limitation='Declared rules only; no file-content, device/OS, encryption capability, quota, or runtime transfer proof')


def analyze_storage_config(path, manifest, cancel, resolver=None, named_resolver=None):
    work = []
    for component in manifest.get('components', []):
        if component.get('kind') != 'provider':
            continue
        entries = [m for m in component.get('metadata', []) if m.get('name') == 'android.support.FILE_PROVIDER_PATHS']
        for entry in entries:
            work.append(('fileprovider', entry.get('resource', ''), component['name'], len(entries) > 1))
    app = manifest.get('application', {})
    for key in ('fullBackupContent', 'dataExtractionRules'):
        ref = app.get(key)
        if ref and ref not in ('true', 'false'):
            work.append((key, ref, '', False))
    inventory = dict(status='DECLARATION_INVENTORY', allowBackup=app.get('allowBackup', 'true (default)'),
                     fullBackupContent=app.get('fullBackupContent', 'platform default'),
                     dataExtractionRules=app.get('dataExtractionRules', 'not declared'), resources=[],
                     limitation='Not effective runtime policy, installation validity, URI grant, or sensitive-data exposure proof')
    findings, diagnostics, consumed = [], [], 0
    if len(work) > 32:
        diagnostics.append('Storage XML resource count budget exceeded; remaining declarations not evaluated')
    for kind, reference, owner, duplicate in work[:32]:
        cancel.check()
        row = dict(kind=kind, reference=reference, component=owner, status='UNKNOWN')
        try:
            if duplicate:
                raise ValueError('Duplicate FileProvider metadata')
            if consumed >= 4 * MAX_XML:
                raise ValueError('Aggregate XML byte budget exceeded')
            data, resource, configuration, mapping = read_xml(path, reference, cancel, resolver, named_resolver)
            consumed += len(data)
            if consumed > 4 * MAX_XML:
                raise ValueError('Aggregate XML byte budget exceeded')
            parsed = parse_rules(data, kind, cancel)
            row.update(status='PARSED_DECLARATIONS', resource=resource, configuration=configuration, mapping=mapping, **parsed)
            if configuration == 'default-only':
                diagnostics.append('Storage XML default configuration only: ' + reference)
            for p in parsed.get('paths', []):
                if p['review_reasons']:
                    findings.append(Finding('AOS-STORAGE-PATH-001', 'Review broad FileProvider path: ' + p['name'],
                        'Declared path range requires review. Provider implementation, caller permissions and actual URI grants are not proven.',
                        'STORAGE', type='REVIEW', confidence='MEDIUM', analysis_level='L0',
                        location=Location(file=resource, class_name=owner), evidence=[str(p)],
                        recommendation='Restrict shared paths and verify least-privilege URI grants and file contents.'))
        except Cancelled:
            raise
        except (OSError, BadZipFile, ValueError, RuntimeError, KeyError, TypeError, ET.ParseError, DefusedXmlException) as exc:
            row['reason'] = str(exc)
            diagnostics.append('Storage configuration unresolved: ' + reference + ': ' + str(exc))
        inventory['resources'].append(row)
    return inventory, findings, diagnostics
