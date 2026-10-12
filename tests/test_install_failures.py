import importlib.util
from pathlib import Path
import sys


def test_deployment_failure_cases(tmp_path):
    path = Path(__file__).resolve().parents[1] / 'tools/validate_install_failures.py'
    spec = importlib.util.spec_from_file_location('install_failures', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Source regression is separate from the actual wheel-only deployment run.
    source = str(path.parents[1] / 'src')
    paths = [source, *[str(Path(p).resolve()) for p in sys.path if p]]
    launcher = ['-I', '-c', f'import sys, runpy; sys.path[:0] = {paths!r}; '
                'runpy.run_module("analyzer", run_name="__main__")']
    assert len(module.validate(sys.executable, tmp_path, module_command=launcher)) == 8
