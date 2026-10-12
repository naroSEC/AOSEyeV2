import csv
import json
from copy import deepcopy

import pytest

from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.report_export import export_report
from analyzer.core.models import AnalysisResult, Finding


def result():
    return AnalysisResult('fixture.apk', 'a' * 64, findings=[Finding('rule', '=1+1<script>alert(1)</script>',
        'detail', 'NETWORK', evidence=['<img src=x onerror=alert(1)>'])])


@pytest.mark.parametrize('format,suffix', [('html', 'html'), ('csv', 'csv'), ('ir-json', 'json')])
def test_exports_no_clobber_and_roundtrip(tmp_path, format, suffix):
    data = result()
    before = deepcopy(data)
    output = tmp_path / ('report.' + suffix)
    export_report(data, output, format)
    text = output.read_text(encoding='utf-8')
    if format == 'html':
        assert '<script>' not in text and '&lt;script&gt;' in text and 'PARTIAL ANALYSIS' in text
    elif format == 'csv':
        with output.open(encoding='utf-8', newline='') as stream:
            row = list(csv.DictReader(stream))[0]
        assert row['title'].startswith("'=1+1") and row['partial'] == 'True'
    else:
        value = json.loads(text)
        assert value['kind'] == 'aoseye-normalized-dex-ir' and value['input_sha256'] == data.sha256
    with pytest.raises(OSError):
        export_report(data, output, format)
    assert output.read_text(encoding='utf-8') == text and data == before


def test_cancel_and_size_limit(tmp_path, monkeypatch):
    import analyzer.app.report_export as module
    token = Cancellation()
    token.cancel()
    output = tmp_path / 'report.html'
    with pytest.raises(Cancelled):
        export_report(result(), output, 'html', token)
    monkeypatch.setattr(module, 'MAX_REPORT_BYTES', 1)
    with pytest.raises(ValueError):
        export_report(result(), output, 'html')
    assert not output.exists() and not list(tmp_path.iterdir())


def test_writer_counts_utf8_without_tell(monkeypatch):
    import analyzer.app.report_export as module
    class Stream:
        def write(self, text):
            return len(text)
    monkeypatch.setattr(module, 'MAX_REPORT_BYTES', 6)
    writer = module._BoundedWriter(Stream(), Cancellation())
    assert writer.write('한글') == 2 and writer.size == 6
    with pytest.raises(ValueError):
        writer.write('a')
    assert writer.size == 6
