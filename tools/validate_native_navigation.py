"""Check one saved project's live JEB reference page without re-running analysis."""
import argparse
from collections import Counter
from pathlib import Path
from analyzer.app.project_manager import open_project, write_json
from analyzer.app.settings import Settings
from analyzer.app.jobs import Cancellation
from analyzer.backends.jeb.backend import JebBackend, file_hash
from analyzer.core.navigation import native_reference_page, bytecode_location


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('--method', required=True)
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    result = open_project(args.project)
    original = Path(result.input_path)
    if not original.exists() or file_hash(original) != result.sha256:
        raise ValueError('Original APK is missing or changed')
    cancel = Cancellation()
    with JebBackend(Settings()) as backend:
        backend.program = result.program
        backend.input_path = original
        backend.input_sha256 = result.sha256
        page = backend.get_jeb_xrefs(args.method, cancel)
        checked, links = native_reference_page(result.program, args.method, page, cancel)
        for link in links:
            bytecode_location(result.program, link['method'], link['offset'], link['unit'])
    report = dict(project=str(args.project), method=args.method, total=checked['total'],
                  shown=checked['shown'], has_more=checked['has_more'], links=links,
                  validation_counts=dict(Counter(item['target_validation'] for item in checked['items'])),
                  items=checked['items'], scope='Live JEB XREF check, not a new APK security analysis')
    write_json(args.output, report)
    print(dict(total=report['total'], links=len(links), validation_counts=report['validation_counts']))
