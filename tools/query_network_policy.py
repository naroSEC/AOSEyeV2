"""Query saved NSC policy without JEB, the original APK, DNS, or network access."""
import argparse
import json
from pathlib import Path
from analyzer.app.project_manager import open_project
from analyzer.analyzers.network_config import select_cleartext_policy

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('--host', action='append', required=True)
    args = parser.parse_args()
    project = open_project(args.project)
    policy = project.manifest.get('network_security_config', {})
    print(json.dumps([select_cleartext_policy(policy, host) for host in args.host], indent=2, ensure_ascii=True))
