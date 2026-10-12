import json
from pathlib import Path
import subprocess
import sys
from analyzer.app.project_manager import save_project
from analyzer.core.models import AnalysisResult, Program, Method, Instruction


def test_isolated_loading_and_virtualized_reference_benchmark(tmp_path):
    signature = 'Ltest/C;->m()V'
    field = 'Ltest/C;->value:I'
    p = Program(methods={signature: Method(signature, instructions=[
        Instruction(i * 2, 'sget', target=field) for i in range(300)], unit='fixture-unit')})
    source, output = tmp_path / 'source.json', tmp_path / 'metrics.json'
    save_project(source, AnalysisResult('fixture.apk', 'abc', program=p))
    before = source.read_bytes()
    tool = Path(__file__).resolve().parents[1] / 'tools/benchmark_project_loading.py'
    run = subprocess.run([sys.executable, str(tool), str(source), '-o', str(output)],
                         capture_output=True, timeout=30)
    assert run.returncode == 0, run.stderr.decode(errors='replace')
    report = json.loads(output.read_text())[0]
    assert report['verified_locations'] == 300
    assert all(sample['links'] == 300 for sample in report['links'])
    assert report['load']['after']['rss_mib'] > 0
    assert source.read_bytes() == before
