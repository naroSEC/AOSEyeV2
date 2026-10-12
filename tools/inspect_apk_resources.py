"""Read JEB's default XML resource inventory without DEX export or APK execution."""
import argparse
import json
from pathlib import Path
from analyzer.app.jobs import Cancellation
from analyzer.app.settings import Settings
from analyzer.backends.jeb.backend import JebBackend, file_hash
from analyzer.analyzers.manifest import analyze_manifest
from analyzer.analyzers.network_config import analyze_network_config, select_cleartext_policy
from analyzer.app.project_manager import write_json

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('--reference')
    parser.add_argument('-o', '--output', type=Path)
    parser.add_argument('--host', action='append', default=[], help='Bare DNS host; repeatable; no network access')
    args = parser.parse_args()
    if args.reference and args.host:
        parser.error('--host is for the Manifest-selected network policy, not arbitrary XML references')
    if args.output and (args.output.exists() or args.output.resolve() == args.apk.resolve()):
        parser.error('Output must be a new file distinct from the APK')
    with JebBackend(Settings()) as backend:
        backend.input_path = args.apk.resolve()
        backend.input_sha256 = file_hash(backend.input_path)
        value = backend.resolve_network_xml(args.reference, Cancellation()) if args.reference else backend._run('resources', Cancellation(), **backend._input_request())
        if not args.reference:
            manifest, _ = analyze_manifest(value.pop('manifest'))
            policy, _, diagnostics = analyze_network_config(args.apk, manifest, Cancellation(), backend.resolve_network_xml, backend.resolve_ca_resource)
            value.update(network_security_config=policy, diagnostics=diagnostics)
            value['host_policies'] = [select_cleartext_policy(policy or {}, host) for host in args.host]
        if args.output:
            write_json(args.output, value)
            print('Resource evidence saved: ' + str(args.output))
        else:
            print(json.dumps(value, indent=2))
