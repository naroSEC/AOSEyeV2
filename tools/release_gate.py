"""Read-only release evidence assessment. Does not publish or approve a release."""
import argparse
import hashlib
import json
from email.parser import BytesParser
from pathlib import Path
from zipfile import ZipFile
from defusedxml import ElementTree

CHECKS = {'install', 'dependencies', 'installed-files', 'console-help', 'module-help', 'gui-smoke',
          'probe', 'inspect', 'analyze', 'reopen', 'export-html', 'export-csv', 'export-ir-json', 'export-verify'}
APPROVALS = {'requirements_scope', 'interactive_gui', 'clean_machine', 'real_apk_limits',
             'licensing', 'distribution_and_support'}


def read_json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate evidence key')
            value[key] = item
        return value
    with path.open('rb') as stream:
        data = stream.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError('Evidence size limit')
    return json.loads(data, object_pairs_hook=unique)


def assess(wheel, installation, regression, acceptance, root):
    blockers = []
    with wheel.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    # Compare packaged source/resources to the current tree, without extracting.
    expected = {p.relative_to(root / 'src').as_posix(): p for p in (root / 'src/analyzer').rglob('*')
                if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py', '.qml', '.yaml')}
    with ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or any(n.lower().endswith(('.apk', '.jar')) for n in names):
            blockers.append('WHEEL_CONTENT_POLICY')
        metadata = [n for n in names if n.endswith('.dist-info/METADATA')]
        license_ok = len(metadata) == 1
        if license_ok:
            name = metadata[0]
            license_ok = archive.getinfo(name).file_size <= 8 * 1024 * 1024
            if license_ok:
                headers = BytesParser().parsebytes(archive.read(name))
                license_ok = (headers.get_all('License-Expression') == ['MIT'] and
                              set(headers.get_all('License-File', [])) == {'LICENSE', 'THIRD_PARTY_NOTICES.md'})
            for leaf in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
                member = name.rsplit('/', 1)[0] + '/licenses/' + leaf
                expected_license = root / leaf
                if (member not in names or not expected_license.is_file() or
                        archive.getinfo(member).file_size > 8 * 1024 * 1024 or
                        archive.read(member) != expected_license.read_bytes()):
                    license_ok = False
        if not license_ok:
            blockers.append('WHEEL_LICENSE_METADATA_OR_FILES_MISMATCH')
        actual = {n for n in names if n.startswith('analyzer/') and n.endswith(('.py', '.qml', '.yaml'))}
        if not expected or actual != set(expected):
            blockers.append('WHEEL_SOURCE_INVENTORY_MISMATCH')
        for name in actual & set(expected):
            info = archive.getinfo(name)
            if info.file_size > 8 * 1024 * 1024 or archive.read(name) != expected[name].read_bytes():
                blockers.append('WHEEL_SOURCE_BYTES_MISMATCH')
                break
    report = read_json(installation)
    rows = report.get('checks', []) if type(report) is dict else []
    if (type(report) is not dict or report.get('sha256') != digest or report.get('passed') is not True or
            type(rows) is not list or len(rows) != len(CHECKS) or
            any(type(row) is not dict or type(row.get('returncode')) is not int or row['returncode'] != 0 for row in rows) or
            {row.get('name') for row in rows} != CHECKS):
        blockers.append('INSTALLATION_EVIDENCE_INVALID_OR_DIFFERENT_WHEEL')
    with regression.open('rb') as stream:
        xml = stream.read(8 * 1024 * 1024 + 1)
    if len(xml) > 8 * 1024 * 1024:
        raise ValueError('Regression evidence size limit')
    suites = list(ElementTree.fromstring(xml).iter('testsuite'))
    cases = [case for suite in suites for case in suite.findall('testcase')]
    if (len(suites) != 1 or suites[0].get('name') != 'aoseye.' + digest or not cases or
            int(suites[0].get('tests', '-1')) != len(cases) or
            any(int(suites[0].get(key, '-1')) != 0 for key in ('errors', 'failures', 'skipped')) or
            any(case.find(tag) is not None for case in cases for tag in ('failure', 'error', 'skipped'))):
        blockers.append('REGRESSION_EVIDENCE_INVALID_OR_DIFFERENT_WHEEL')
    approval = read_json(acceptance)
    valid_approval = type(approval) is dict and approval.get('wheel_sha256') == digest
    if not valid_approval:
        blockers.append('ACCEPTANCE_NOT_BOUND_TO_WHEEL')
    for key in sorted(APPROVALS):
        row = approval.get(key) if valid_approval else None
        if (type(row) is not dict or row.get('approved') is not True or
                any(type(row.get(field)) is not str or not row[field].strip() for field in ('reviewer', 'evidence'))):
            blockers.append('OWNER_ACCEPTANCE_REQUIRED:' + key)
    return dict(status='BLOCKED' if blockers else 'READY_FOR_OWNER_RELEASE_REVIEW',
                wheel=str(wheel.resolve()), sha256=digest, regression_cases=len(cases), blockers=blockers,
                scope='Local evidence consistency, not independent attestation, legal clearance or publication')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('wheel', 'installation', 'regression', 'acceptance'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        report = assess(args.wheel, args.installation, args.regression, args.acceptance, args.root)
    except Exception as exc:
        # Invalid evidence must fail closed; do not print its potentially sensitive contents.
        print(json.dumps({'status': 'BLOCKED', 'blockers': ['EVIDENCE_READ_OR_VALIDATION_ERROR'],
                          'error_type': type(exc).__name__}))
        return 2
    print(json.dumps(report, indent=2))
    return 2 if report['blockers'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
