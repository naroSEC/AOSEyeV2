from pathlib import Path
import re
from zipfile import ZipFile, BadZipFile
from analyzer.app.jobs import Cancellation
from analyzer.core.models import Finding, Location
from analyzer.analyzers.asset_database import inspect_database
from analyzer.analyzers.asset_config import inspect_config, internal_url, inspect_assignment_credentials
from analyzer.analyzers.network_certificates import inspect_certificate_bytes
from cryptography.exceptions import UnsupportedAlgorithm

SENSITIVE = {'.env', '.properties', '.json', '.xml', '.yaml', '.yml', '.db', '.sqlite',
             '.sqlite3', '.pem', '.key', '.p12', '.pfx', '.jks', '.keystore', '.bak',
             '.backup', '.old', '.zip', '.js', '.map', '.txt', '.conf', '.config', '.crt', '.cer', '.der', '.ini', '.credentials'}
PATTERNS = [
    ('Private key material', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), 'MEDIUM'),
    ('Credential assignment', re.compile(r'(?i)["\']?(?:api[_-]?key|access[_-]?token|secret|password|client_secret)["\']?\s*[:=]\s*["\']?([^\s"\',;}]{8,})'), 'LOW'),
    ('JWT-shaped value', re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'), 'LOW'),
    ('Google API key candidate', re.compile(r'AIza[0-9A-Za-z_-]{35}'), 'INFO'),
    ('Internal or development URL', re.compile(r'https?://[^\s"<>]+'), 'INFO'),
]


def inspect_apk(path: Path, cancel: Cancellation) -> tuple[list, bytes, list, list]:
    files, findings, diagnostics = [], [], []
    manifest = b''
    consumed = 0
    with ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 100000:
            raise ValueError('APK contains too many ZIP entries')
        names = set()
        for entry in entries:
            cancel.check()
            if entry.filename in names:
                diagnostics.append('Duplicate archive path: ' + entry.filename)
                continue
            names.add(entry.filename)
            files.append(dict(path=entry.filename, size=entry.file_size))
            selected = entry.filename == 'AndroidManifest.xml' or entry.filename.startswith(('assets/', 'res/raw/', 'res/xml/'))
            if not selected or entry.is_dir():
                continue
            if entry.file_size > 8 * 1024 * 1024 or consumed + entry.file_size > 128 * 1024 * 1024:
                diagnostics.append('ZIP content scan budget: skipped ' + entry.filename)
                continue
            if entry.file_size / max(entry.compress_size, 1) > 1000:
                diagnostics.append('Suspicious compression ratio: skipped ' + entry.filename)
                continue
            try:
                with archive.open(entry) as stream:
                    content = stream.read(8 * 1024 * 1024 + 1)
            except (RuntimeError, BadZipFile) as exc:
                diagnostics.append(f'Cannot read {entry.filename}: {exc}')
                continue
            consumed += len(content)
            if len(content) > 8 * 1024 * 1024:
                diagnostics.append('Oversized decoded entry: ' + entry.filename)
                continue
            if entry.filename == 'AndroidManifest.xml':
                manifest = content
                continue
            name = Path(entry.filename)
            if name.suffix.lower() not in SENSITIVE and name.name != '.env':
                continue
            if name.suffix.lower() in {'.db', '.sqlite', '.sqlite3', '.p12', '.pfx', '.jks', '.keystore', '.bak', '.backup'}:
                findings.append(Finding('AOS-ASSET-001', 'Sensitive file candidate',
                    'File type warrants review; contents and exposure are not established.', 'SECRETS',
                    location=Location(file=entry.filename), evidence=[f'{entry.file_size} bytes']))
            if name.suffix.lower() in {'.db', '.sqlite', '.sqlite3'}:
                database_findings, database_diagnostics = inspect_database(content, entry.filename, cancel)
                findings.extend(database_findings)
                diagnostics.extend(database_diagnostics)
            text = content.decode('utf-8', errors='replace')
            if (name.suffix.lower() in {'.crt', '.cer', '.der'} or
                    name.suffix.lower() == '.pem' and b'-----BEGIN CERTIFICATE-----' in content):
                try:
                    certificate = inspect_certificate_bytes(content, cancel)
                except (ValueError, UnsupportedAlgorithm):
                    diagnostics.append('Certificate asset unsupported, malformed or over budget: ' + entry.filename)
                else:
                    findings.append(Finding('AOS-ASSET-006', 'Bundled public X.509 certificate data',
                        'Certificate structure was parsed; public certificates are not private keys. '
                        'Trust-anchor use, validity, signature/chain correctness and runtime use are not established.',
                        'INFO', type='INFORMATION', severity='INFO', confidence='HIGH', analysis_level='L2',
                        location=Location(file=entry.filename),
                        evidence=[f"Encoding: {certificate['encoding']}; certificates: {certificate['certificate_count']}"],
                        validation={'certificate_structure': 'PARSED', 'trust_usage': 'UNKNOWN',
                                    'certificate_chain': 'UNKNOWN'},
                        recommendation='Review intended trust or pinning use; certificate presence alone does not warrant key rotation.'))
            public_keys = set()
            if name.suffix.lower() in {'.env', '.properties', '.ini', '.conf', '.credentials'} or name.name == '.env':
                config_findings, config_diagnostics = inspect_assignment_credentials(content, entry.filename, cancel)
                findings.extend(config_findings)
                diagnostics.extend(config_diagnostics)
            if name.suffix.lower() == '.json':
                config_findings, config_diagnostics, public_keys = inspect_config(content, entry.filename, cancel)
                findings.extend(config_findings)
                diagnostics.extend(config_diagnostics)
            for n, (title, pattern, severity) in enumerate(PATTERNS):
                cancel.check()
                accepted = 0
                for match in pattern.finditer(text):
                    cancel.check()
                    if n == 4 and not internal_url(match.group()):
                        continue
                    if accepted == 20:
                        diagnostics.append(f'Asset pattern matches truncated (AOS-SECRET-{n + 1:03}, limit 20): ' + entry.filename)
                        break
                    accepted += 1
                    public_api = (n == 1 and match.group(1) in public_keys
                                  and re.match(r'["\']?api[_-]?key["\']?\s*[:=]', match.group(), re.I))
                    line = text.count('\n', 0, match.start()) + 1
                    findings.append(Finding(f'AOS-SECRET-{n + 1:03}', title,
                        ('Firebase client API configuration is normally public; verify service restrictions separately.'
                         if public_api else 'A static candidate was found. Verify validity, restrictions and runtime use.'),
                        'SECRETS', severity='INFO' if public_api else severity, confidence='MEDIUM',
                        location=Location(file=entry.filename, offset=match.start()),
                        evidence=[f'Line {line}; matched value redacted ({len(match.group())} characters)'],
                        recommendation='Validate scope and restrictions; remove or rotate exposed credentials if confirmed.'))
    return files, manifest, findings, diagnostics
