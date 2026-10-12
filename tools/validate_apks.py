"""Local real-APK regression runner. Requires the optional test dependency psutil."""
import argparse
from collections import Counter
from pathlib import Path
from threading import Event, Thread
import time
from zipfile import ZipFile
import psutil

from analyzer.app.application import AnalysisApplication
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.project_manager import save_project, write_json
from analyzer.app.settings import Settings
from analyzer.analyzers.manifest import external_entries


def validate(path, directory, save, settings=None, max_seconds=900, max_rss_mib=4096, min_available_mib=768):
    if min(max_seconds, max_rss_mib) <= 0 or min_available_mib < 0:
        raise ValueError('Invalid validation resource limits')
    directory.mkdir(parents=True, exist_ok=False)
    application = AnalysisApplication(settings or Settings(cache_enabled=False))
    backend = application.backend
    cancel, stopped = Cancellation(), Event()
    peaks = dict(python_rss=0, java_rss=0, sampled_combined_rss=0)
    guard = dict(reason=None, observed_available_bytes=None, observed_combined_rss=None)
    telemetry = []
    start = time.monotonic()
    def sample():
        parent = psutil.Process()
        next_sample = 0
        while not stopped.wait(0.25):
            try:
                python_memory, memory, java_cpu = parent.memory_info().rss, 0, None
                peaks['python_rss'] = max(peaks['python_rss'], python_memory)
                if backend.session.pid:
                    java = psutil.Process(backend.session.pid)
                    memory = java.memory_info().rss + sum(p.memory_info().rss for p in java.children(recursive=True))
                    peaks['java_rss'] = max(peaks['java_rss'], memory)
                    try:
                        cpu = java.cpu_times()
                        java_cpu = cpu.user + cpu.system
                    except psutil.Error:
                        pass
                combined = python_memory + memory
                available = psutil.virtual_memory().available
                peaks['sampled_combined_rss'] = max(peaks['sampled_combined_rss'], combined)
                elapsed = time.monotonic() - start
                if elapsed >= next_sample and len(telemetry) < 1200:
                    work = getattr(backend.session, '_directory', None)
                    streams = []
                    if work is not None:
                        try:
                            streams = [p.stat().st_size for p in Path(work.name).glob('*.methods.jsonl')]
                        except OSError:
                            pass
                    row = dict(seconds=round(elapsed, 3), python_rss=python_memory, java_rss=memory,
                               java_cpu_seconds=java_cpu, method_stream_bytes=sum(streams),
                               method_stream_present=bool(streams), system_available_bytes=available)
                    telemetry.append(row)
                    print(f'{path.name}: monitor {row["seconds"]}s; RSS={combined // 2**20}MiB; '
                          f'JVM CPU={java_cpu}; method-stream={sum(streams)} bytes', flush=True)
                    next_sample = elapsed + 30
                if guard['reason'] is None:
                    if time.monotonic() - start > max_seconds:
                        guard['reason'] = 'Elapsed time guard reached'
                    elif combined > max_rss_mib * 2**20:
                        guard['reason'] = 'Combined Python/JEB RSS guard reached'
                    elif available < min_available_mib * 2**20:
                        guard['reason'] = 'System available-memory guard reached'
                    if guard['reason']:
                        guard.update(observed_available_bytes=available, observed_combined_rss=combined)
                        cancel.cancel()
            except psutil.Error:
                pass
    watcher = Thread(target=sample, daemon=True)
    watcher.start()
    stages = []
    summary = dict(input=str(path.resolve()), complete=False, stages=stages)
    def progress(percent, stage):
        stages.append(dict(percent=percent, stage=stage, seconds=round(time.monotonic() - start, 3)))
        print(f'{path.name}: {percent}% {stage} ({stages[-1]["seconds"]}s)', flush=True)
    try:
        result = application.analyze(path, cancel, progress)
        analysis_seconds = time.monotonic() - start
        with ZipFile(path) as archive:
            dex_files = [i.filename for i in archive.infolist()
                         if i.filename.startswith('classes') and i.filename.endswith('.dex')]
        summary = dict(input=str(path.resolve()), sha256=result.sha256, bytes=path.stat().st_size,
            dex_files=dex_files, dex_units=result.program.dex_units,
            declarations=len(result.program.method_index), bodies=len(result.program.methods),
            classes=len(result.program.classes), fields=len(result.program.fields),
            instructions=sum(len(m.instructions) for m in result.program.methods.values()),
            manifest=dict(package=result.manifest.get('package'), target_sdk=result.manifest.get('target_sdk'),
                          components=len(result.manifest.get('components', [])),
                          exported=sum(c['exported'] is True for c in result.manifest.get('components', []))),
            findings_by_type=dict(Counter(f.type for f in result.findings)),
            findings_by_level=dict(Counter(f.analysis_level for f in result.findings)),
            complete=result.complete, diagnostics=result.diagnostics, stages=stages,
            flow_coverage=result.provenance.get('flow_coverage', {}),
            analysis_seconds=round(analysis_seconds, 3), evidence_checks=[])
        candidates = sorted(external_entries(result.manifest, result.program.methods,
                            result.program.class_hierarchy, result.program.method_index))
        prefix = 'L' + (result.manifest.get('package') or '').replace('.', '/')
        candidates += [m for m in result.program.methods if m.startswith(prefix)]
        candidates += list(result.program.methods)
        for method in list(dict.fromkeys(candidates))[:2]:
            check = dict(method=method)
            try:
                source = backend.get_decompiled_source(method, cancel)
                ast = backend.get_ast(method, cancel)
                refs = backend.get_jeb_xrefs(method, cancel)
                offsets = {i.offset for i in result.program.methods[method].instructions}
                calls = [n for n in ast['nodes'] if n['kind'] == 'Call' and n['offset'] is not None]
                check.update(source_characters=len(source), ast_nodes=len(ast['nodes']),
                    ast_truncated=ast['truncated'], ast_call_offsets=len(calls),
                    ast_offsets_in_dex=sum(n['offset'] in offsets for n in calls),
                    xref_count=refs['total'], cfg_blocks=len(backend.get_cfg(method)))
            except Exception as exc:
                if isinstance(exc, Cancelled):
                    raise
                check['error'] = str(exc)
            summary['evidence_checks'].append(check)
        if save:
            cancel.check()
            progress(100, 'Saving project')
            save_project(directory / 'project.json', result)
            summary['project_bytes'] = (directory / 'project.json').stat().st_size
        summary.update(session=backend.session_info, capabilities=backend.capabilities,
                       total_seconds=round(time.monotonic() - start, 3))
        cancel.check()
    except Exception as exc:
        summary.update(validation_status='CANCELLED' if isinstance(exc, Cancelled) else 'FAILED',
                       error=str(exc), total_seconds=round(time.monotonic() - start, 3))
    finally:
        backend.close()
        stopped.set()
        watcher.join()
    summary['peak_memory'] = peaks
    summary['jeb_phase_trace'] = getattr(backend.session, 'phase_trace', [])
    summary['telemetry'] = telemetry
    summary['jvm_heap_mib'] = application.settings.jvm_heap_mib
    summary['max_export_mib'] = application.settings.max_export_mib
    summary['max_index_entries'] = application.settings.max_index_entries
    summary['max_index_mib'] = application.settings.max_index_mib
    summary['requested_index_order'] = application.settings.index_order
    summary['guard'] = dict(guard, max_seconds=max_seconds, max_rss_mib=max_rss_mib,
                            min_available_mib=min_available_mib, sample_interval_seconds=0.25)
    summary.setdefault('validation_status', 'EVIDENCE_FAILED' if any(
        row.get('error') for row in summary.get('evidence_checks', [])) else 'FINISHED')
    summary['bridge_closed'] = backend.session.pid is None
    write_json(directory / 'summary.json', summary)
    print(f'{path.name}: {summary["validation_status"]}; methods={summary.get("bodies")}; complete={summary["complete"]}; report={directory}', flush=True)
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('apks', nargs='+', type=Path)
    parser.add_argument('--output', type=Path, default=Path('build/real-apk-tests'))
    parser.add_argument('--save-project', action='store_true')
    parser.add_argument('--aapt2-path', default='')
    parser.add_argument('--jvm-heap-mib', type=int, default=4096)
    parser.add_argument('--max-export-mib', type=int, default=64)
    parser.add_argument('--max-index-entries', type=int, default=20000)
    parser.add_argument('--max-index-mib', type=int, default=8)
    parser.add_argument('--index-order', choices=['native', 'manifest-first'], default='native')
    parser.add_argument('--max-seconds', type=float, default=900)
    parser.add_argument('--max-rss-mib', type=int, default=4096)
    parser.add_argument('--min-available-mib', type=int, default=768)
    args = parser.parse_args()
    failed = False
    for path in args.apks:
        summary = validate(path, args.output / path.stem, args.save_project,
                 Settings(cache_enabled=False, aapt2_path=args.aapt2_path, jvm_heap_mib=args.jvm_heap_mib,
                          max_export_mib=args.max_export_mib, max_index_entries=args.max_index_entries,
                          max_index_mib=args.max_index_mib, index_order=args.index_order),
                 args.max_seconds, args.max_rss_mib, args.min_available_mib)
        failed |= summary['validation_status'] != 'FINISHED' or not summary['complete']
    raise SystemExit(2 if failed else 0)
