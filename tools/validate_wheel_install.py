"""Install a wheel in a fresh external venv and validate its entry points.

The temporary validation directory is deliberately retained for inspection.
No APK is installed or executed. JEB checks require a licensed local install.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import venv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel', type=Path)
    parser.add_argument('--jeb-path', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True,
                        help='Generated flow-fixture.apk containing test.Main.onCreate (not an arbitrary APK)')
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    apk = args.apk.resolve(strict=True)
    jeb = args.jeb_path.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='aoseye-wheel-'))
    print(f'Validation directory: {root}', flush=True)
    environment = root / 'venv'
    venv.EnvBuilder(with_pip=True).create(environment)
    scripts = environment / ('Scripts' if os.name == 'nt' else 'bin')
    python = scripts / ('python.exe' if os.name == 'nt' else 'python')
    cli = scripts / ('aoseye.exe' if os.name == 'nt' else 'aoseye')
    env = dict(os.environ)
    for name in ('PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV', 'AOSEYE_JEB_PATH'):
        env.pop(name, None)
    env.update(LOCALAPPDATA=str(root / 'userdata'), QT_QPA_PLATFORM='offscreen',
               PYTHONNOUSERSITE='1', PYTHONUTF8='1')
    report = dict(wheel=str(wheel), sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
                  directory=str(root), checks=[])

    def run(label, command, allowed=(0,)):
        start = time.monotonic()
        completed = subprocess.run([str(item) for item in command], cwd=root, env=env,
                                   capture_output=True, text=True, encoding='utf-8',
                                   errors='replace', timeout=900)
        (root / f'{label}.stdout.txt').write_text(completed.stdout, encoding='utf-8')
        (root / f'{label}.stderr.txt').write_text(completed.stderr, encoding='utf-8')
        report['checks'].append(dict(name=label, returncode=completed.returncode,
                                     seconds=round(time.monotonic() - start, 3)))
        print(f'{label}: exit {completed.returncode}', flush=True)
        if completed.returncode not in allowed:
            raise RuntimeError(f'{label} failed; see logs in {root}')

    try:
        run('install', [python, '-I', '-m', 'pip', 'install', wheel])
        run('dependencies', [python, '-I', '-m', 'pip', 'check'])
        run('installed-files', [python, '-I', '-c', '''
import analyzer, importlib.metadata, json, pathlib, sys
base = pathlib.Path(analyzer.__file__).resolve().parent
assert base.is_relative_to(pathlib.Path(sys.prefix).resolve()), base
assert sys.prefix != sys.base_prefix
files = list(importlib.metadata.files('aoseye'))
assert not any(str(f).lower().endswith(('.jar', '.apk')) for f in files)
for pattern in ('gui/qml/*.qml', 'backends/jeb/scripts/*.py', 'core/rules/*.yaml'):
    resources = list(base.glob(pattern))
    assert resources and all(p.stat().st_size for p in resources), pattern
print(json.dumps(dict(package=str(base), prefix=sys.prefix, python=sys.version,
    versions={name: importlib.metadata.version(name) for name in
    ('aoseye', 'PySide6', 'PyYAML', 'defusedxml', 'cryptography')}), indent=2))
'''])
        run('console-help', [cli, '--help'])
        run('module-help', [python, '-I', '-m', 'analyzer', '--help'])
        run('gui-smoke', [cli, 'gui-smoke'])
        run('probe', [cli, 'probe', '--jeb-path', jeb])
        run('inspect', [cli, 'inspect', apk, '--jeb-path', jeb, '--method',
                        'Ltest/Main;->onCreate(Landroid/os/Bundle;)V',
                        '-o', root / 'evidence.json'])
        # Code 2 denotes a saved partial analysis, not necessarily a process failure.
        run('analyze', [cli, 'analyze', apk, '--jeb-path', jeb,
                        '-o', root / 'project.json'], allowed=(0, 2))
        run('reopen', [python, '-I', '-c', '''
import json
from pathlib import Path
from analyzer.app.project_manager import open_project
evidence = json.loads(Path('evidence.json').read_text(encoding='utf-8'))
assert evidence['indexed_body_count'] > 0
assert evidence['source'] and evidence['ast']
result = open_project(Path('project.json'))
assert result.program.methods and result.findings
print(json.dumps(dict(methods=len(result.program.methods), findings=len(result.findings),
                      complete=result.complete), indent=2))
'''])
        for kind, extension in (('html', 'html'), ('csv', 'csv'), ('ir-json', 'json')):
            run('export-' + kind, [cli, 'export', root / 'project.json', '--format', kind,
                                  '-o', root / ('report.' + extension)])
        run('export-verify', [python, '-I', '-c', '''
import json, csv
from pathlib import Path
from analyzer.app.candidate_artifact import open_candidate, compare_origin
from analyzer.app.candidate_analysis import expand_candidate
from analyzer.analyzers.storage_config import parse_rules
from analyzer.app.jobs import Cancellation
assert parse_rules(b'<paths/>', 'fileprovider', Cancellation()) == {'paths': []}
assert 'Content-Security-Policy' in Path('report.html').read_text(encoding='utf-8')
assert json.loads(Path('report.json').read_text(encoding='utf-8'))['kind'] == 'aoseye-normalized-dex-ir'
with Path('report.csv').open(encoding='utf-8', newline='') as stream:
    rows=list(csv.DictReader(stream))
assert rows and all('input_sha256' in r for r in rows)
print('Installed candidate APIs and HTML/CSV/IR exports verified')
'''])
        report['passed'] = True
    except Exception as exc:
        report.update(passed=False, error=str(exc))
        raise
    finally:
        (root / 'validation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f'Report: {root / "validation.json"}', flush=True)


if __name__ == '__main__':
    main()
