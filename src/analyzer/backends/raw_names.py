"""Resolve an explicit raw name via local aapt2, then verify its default JEB mapping.

Shared optional name resolver and read-only diagnostic; never executes the APK.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

from analyzer.app.jobs import Cancellation
from analyzer.app.settings import Settings
from analyzer.backends.jeb.backend import JebBackend, file_hash
from analyzer.analyzers.network_certificates import inspect_trust_resources
from analyzer.analyzers.network_trust import parse_trust
from analyzer.app.project_manager import write_json


def select_raw_name(text, reference):
    return select_resource_name(text, reference, 'raw')


def select_resource_name(text, reference, resource_type):
    if resource_type not in ('raw', 'xml'):
        raise ValueError('Unsupported resource name type')
    if not re.fullmatch(r'@' + resource_type + r'/[A-Za-z0-9_]+', reference):
        raise ValueError('Expected an unqualified @%s/name reference' % resource_type)
    if len(text) > 16 * 1024 * 1024:
        raise ValueError('aapt2 output budget exceeded')
    packages, matches = [], []
    for line in text.splitlines():
        if line.startswith('Package '):
            match = re.fullmatch(r'Package name=([^\s]+) id=([0-9a-fA-F]{2})', line)
            if not match:
                raise ValueError('Unsupported aapt2 package line')
            packages.append(match.groups())
        match = re.fullmatch(r'\s+resource 0x([0-9a-fA-F]{8}) (' + resource_type + r'/[A-Za-z0-9_]+)(?: PUBLIC)?', line)
        if match and match.group(2) == reference[1:]:
            matches.append(int(match.group(1), 16))
    if len(packages) != 1 or len(matches) != 1 or matches[0] >> 24 != int(packages[0][1], 16):
        raise ValueError('Raw name missing, ambiguous or package selection unsupported')
    return dict(reference=reference, resource_id=matches[0], package=packages[0][0],
                name_origin='aapt2 dump resources')


def dump_resources(aapt2, apk, cancel):
    # Temporary files avoid unbounded PIPE buffering; the subprocess never sees a shell.
    limit = 16 * 1024 * 1024
    cancel.check()
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        proc = subprocess.Popen([str(aapt2), 'dump', 'resources', str(apk)],
            stdout=output, stderr=errors, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            deadline = time.monotonic() + 30
            while proc.poll() is None:
                cancel.check()
                if time.monotonic() > deadline:
                    raise ValueError('aapt2 timed out')
                if output.seek(0, 2) > limit or errors.seek(0, 2) > limit:
                    raise ValueError('aapt2 output budget exceeded')
                time.sleep(0.05)
            cancel.check()
            if proc.returncode:
                raise ValueError('aapt2 resource dump failed (exit %s)' % proc.returncode)
            output.seek(0)
            data = output.read(limit + 1)
            if len(data) > limit or errors.seek(0, 2) > limit:
                raise ValueError('aapt2 output budget exceeded')
            return data.decode('utf-8', errors='strict')
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('--aapt2', required=True, type=Path, help='Explicit trusted local aapt2 executable')
    parser.add_argument('--reference', required=True)
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args()
    if args.output and (args.output.exists() or args.output.resolve() == args.apk.resolve()):
        parser.error('Output must be a new file distinct from the APK')
    token = Cancellation()
    apk = args.apk.resolve(strict=True)
    original_hash = file_hash(apk, token)
    selected = select_raw_name(dump_resources(args.aapt2.resolve(strict=True), apk, token), args.reference)
    with JebBackend(Settings()) as backend:
        backend.input_path, backend.input_sha256 = apk, original_hash
        numeric = '@%08x' % selected['resource_id']
        mapped = backend.resolve_ca_resource(numeric, token)
        trust = parse_trust('<network-security-config><base-config><trust-anchors>'
            '<certificates src="' + numeric + '"/></trust-anchors></base-config></network-security-config>',
            None, False, token)
        inspect_trust_resources(apk, trust, token, backend.resolve_ca_resource)
        if file_hash(apk, token) != original_hash:
            raise ValueError('APK changed during resource inspection')
        result = dict(selected, mapping=mapped, input_sha256=original_hash,
            inspection=trust['base_anchors'][0]['resource_inspection'],
            scope='Explicit raw name diagnostic only; not evidence that the app declares this file as a CA')
    if args.output:
        write_json(args.output, result)
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
