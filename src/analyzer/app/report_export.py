"""Offline exports of saved evidence; no external scripts, navigation, or formula execution."""
import csv
from dataclasses import asdict
import html
import json
import os
from pathlib import Path
import tempfile

from analyzer.core.call_coverage import coverage_text

MAX_REPORT_BYTES = 128 * 1024 * 1024


class _BoundedWriter:
    """Count UTF-8 bytes without flushing TextIOWrapper for every JSON token."""

    def __init__(self, stream, cancel):
        self.stream, self.cancel, self.size = stream, cancel, 0

    def write(self, text):
        if self.cancel:
            self.cancel.check()
        size = len(text.encode('utf-8'))
        if self.size + size > MAX_REPORT_BYTES:
            raise ValueError('Report exceeds 128MiB export limit')
        result = self.stream.write(text)
        self.size += size
        return result


def csv_cell(value):
    text = str(value)
    # Spreadsheet import may trim controls/whitespace before interpreting formulas.
    if text.lstrip(' \t\r\n\ufeff').startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


def export_report(result, path, format, cancel=None):
    if format not in ('html', 'csv', 'ir-json'):
        raise ValueError('Unsupported report format')
    path = Path(path)
    if path.suffix.lower() != {'html': '.html', 'csv': '.csv', 'ir-json': '.json'}[format]:
        raise ValueError('Report filename extension does not match format')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.aoseye-report-', dir=path.parent)
    def check(stream):
        if cancel:
            cancel.check()
        if stream.size > MAX_REPORT_BYTES:
            raise ValueError('Report exceeds 128MiB export limit')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as raw_stream:
            stream = _BoundedWriter(raw_stream, cancel)
            check(stream)
            if format == 'csv':
                writer = csv.writer(stream)
                columns = ('id', 'rule_id', 'title', 'type', 'severity', 'confidence', 'verification',
                           'analysis_level', 'method', 'offset', 'description', 'evidence', 'recommendation', 'input_sha256', 'partial')
                writer.writerow(columns)
                for finding in result.findings:
                    row = asdict(finding)
                    row.update(method=finding.location.method, offset=finding.location.offset,
                               evidence='\n'.join(finding.evidence), input_sha256=result.sha256,
                               partial=not result.complete or bool(result.diagnostics) or bool(result.program.diagnostics))
                    writer.writerow([csv_cell(row.get(c, '')) for c in columns])
                    check(stream)
            elif format == 'html':
                esc = lambda value: html.escape(str(value), quote=True)
                stream.write('<!doctype html><html lang="en"><meta charset="utf-8">'
                    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
                    '<title>AOSEye saved analysis</title><style>body{font:16px system-ui;max-width:1100px;margin:2em auto;padding:1em}'
                    'pre{white-space:pre-wrap;overflow-wrap:anywhere}article{border-top:1px solid #bbb;padding:1em 0}</style>'
                    '<h1>AOSEye saved analysis</h1><p>Static candidates, not verified vulnerabilities. Saved scope only.</p><pre>' +
                    esc(('PARTIAL ANALYSIS' if not result.complete or result.diagnostics or result.program.diagnostics else
                         'Complete within configured scope only') + '\nSaved bodies: ' + str(len(result.program.methods)) + '\n' +
                        coverage_text(result.provenance.get('call_target_coverage'))) + '\nInput SHA-256: ' + esc(result.sha256) + '</pre>')
                for f in result.findings:
                    stream.write('<article><h2>' + esc(f.title) + '</h2><p>' +
                        esc(' / '.join((f.severity, f.type, f.verification, f.analysis_level))) + '</p><pre>' +
                        esc(json.dumps(asdict(f), ensure_ascii=False, indent=2)) + '</pre></article>')
                    check(stream)
                stream.write('<h2>Diagnostics</h2><pre>' + esc('\n'.join(result.diagnostics)) + '</pre></html>')
            else:
                # Incremental model encoding avoids copying the full Program via asdict.
                from analyzer.app.project_manager import ModelEncoder
                value = dict(kind='aoseye-normalized-dex-ir', schema=1, input_sha256=result.sha256,
                    complete=result.complete, limitation='Saved normalized DEX DTO, not native JEB optimizer IR or runtime dispatch',
                    provenance=result.provenance, program=result.program)
                for part in ModelEncoder(ensure_ascii=True, separators=(',', ':'), allow_nan=False).iterencode(value):
                    stream.write(part)
                    check(stream)
            check(stream)
            raw_stream.flush()
            os.fsync(raw_stream.fileno())
        if cancel:
            cancel.check()
        os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
