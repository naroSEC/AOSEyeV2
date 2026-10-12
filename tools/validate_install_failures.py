"""Exercise expected deployment failures without changing user settings."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def validate(python, root, *, module_command=None):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    cases = []
    for case in ('malformed-settings', 'invalid-settings', 'missing-jeb', 'missing-java',
                 'invalid-override', 'missing-input', 'logs-unwritable', 'inspect-failure'):
        work = root / case
        work.mkdir()
        data = work / 'AOSEye'
        data.mkdir()
        settings = data / 'settings.json'
        config = dict(jeb_path=str(work / 'missing-jeb'), java=str(work / 'missing-java.exe'))
        command = ['probe']
        expected = 'not found'
        if case == 'malformed-settings':
            content, expected = '{invalid', 'Settings could not be loaded'
        else:
            if case == 'invalid-settings':
                config['timeout_seconds'] = 0
                expected = 'timeout_seconds'
            if case == 'missing-java':
                jar = work / 'fake-jeb/bin/app/jeb.jar'
                jar.parent.mkdir(parents=True)
                jar.touch()  # Only launcher failure is exercised; this is not a JEB binary.
                config['jeb_path'] = str(work / 'fake-jeb')
                expected = 'Could not start Java executable'
            content = json.dumps(config)
        if case == 'invalid-override':
            command += ['--jeb-path', '   ']
            expected = 'Invalid settings path/command'
        output = work / 'existing-report.json'
        output.write_bytes(b'preserve existing report')
        if case == 'missing-input':
            command = ['analyze', str(work / 'missing.apk'), '-o', str(output)]
            expected = 'could not complete'
        if case == 'inspect-failure':
            command = ['inspect', str(work / 'missing.apk'), '--method', 'missing', '-o', str(output)]
            expected = 'not found'
        if case == 'logs-unwritable':
            (data / 'logs').write_text('not a directory', encoding='utf-8')
            expected = 'could not complete'
        settings.write_text(content, encoding='utf-8')
        before = settings.read_bytes()
        env = dict(os.environ, LOCALAPPDATA=str(work), PYTHONUTF8='1', PYTHONNOUSERSITE='1')
        for key in ('PYTHONPATH', 'PYTHONHOME', 'AOSEYE_JEB_PATH'):
            env.pop(key, None)
        launcher = module_command if module_command is not None else ['-I', '-m', 'analyzer']
        completed = subprocess.run([str(python), '-X', 'utf8', *launcher, *command],
                                   cwd=work, env=env, capture_output=True, text=True,
                                   encoding='utf-8', timeout=30)
        combined = completed.stdout + completed.stderr
        (work / 'output.txt').write_text(combined, encoding='utf-8')
        assert completed.returncode == 2, (case, combined)
        assert expected in combined, (case, combined)
        assert 'Traceback (most recent call last)' not in combined, (case, combined)
        assert settings.read_bytes() == before, case
        assert output.read_bytes() == b'preserve existing report', case
        cases.append(dict(case=case, returncode=completed.returncode, preserved=True))
    (root / 'validation.json').write_text(json.dumps(cases, indent=2), encoding='utf-8')
    return cases


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python', type=Path, default=Path(sys.executable))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='aoseye-failures-'))
    print(f'Validation directory: {directory}', flush=True)
    print(f'{len(validate(args.python.resolve(), directory))} failure cases passed')
