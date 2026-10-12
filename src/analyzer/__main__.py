import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from analyzer.app.settings import Settings, data_dir
from analyzer.app.jobs import Cancellation
from analyzer.backends.base import BackendError


def main():
    try:
        return _main()
    except (OSError, ValueError, BackendError) as exc:
        logging.error('AOSEye could not complete the command: %s', exc)
        return 2


def _main():
    parser = argparse.ArgumentParser(description='AOSEye Android security analysis')
    sub = parser.add_subparsers(dest='command')
    analyze = sub.add_parser('analyze')
    analyze.add_argument('input', type=Path)
    analyze.add_argument('-o', '--output', type=Path, required=True)
    analyze.add_argument('--jeb-path')
    analyze.add_argument('--aapt2-path', help='Optional absolute local aapt2 executable; empty disables name resolution')
    analyze.add_argument('--jvm-heap-mib', type=int, help='JEB Java heap limit (512-16384 MiB), not total RSS')
    analyze.add_argument('--max-export-mib', type=int, help='Method JSONL budget (1-256 MiB); hitting it yields partial analysis')
    analyze.add_argument('--max-index-entries', type=int, help='Declaration count per kind (1-200000)')
    analyze.add_argument('--max-index-mib', type=int, help='Encoded declaration accounting budget (1-64 MiB), not RSS')
    analyze.add_argument('--index-order', choices=['native', 'manifest-first'])
    probe = sub.add_parser('probe')
    probe.add_argument('--jeb-path')
    inspect = sub.add_parser('inspect', help='Exercise the persistent JEB bridge without a GUI')
    inspect.add_argument('input', type=Path)
    inspect.add_argument('--method', required=True)
    inspect.add_argument('-o', '--output', type=Path, required=True)
    inspect.add_argument('--jeb-path')
    sub.add_parser('gui-smoke')
    export = sub.add_parser('export', help='Export saved evidence without JEB; new output file only')
    export.add_argument('project', type=Path)
    export.add_argument('--format', choices=['html', 'csv', 'ir-json'], required=True)
    export.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'export':
        from analyzer.app.project_manager import open_project
        from analyzer.app.report_export import export_report
        token = Cancellation()
        export_report(open_project(args.project, cancel=token), args.output, args.format, token)
        return 0
    logs = data_dir() / 'logs'
    logs.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, handlers=[
        RotatingFileHandler(logs / 'aoseye.log', maxBytes=2_000_000, backupCount=3, encoding='utf-8'),
        logging.StreamHandler()], format='%(asctime)s %(levelname)s %(name)s %(message)s')
    try:
        settings = Settings.load()
    except (OSError, ValueError) as exc:
        logging.error('Settings could not be loaded; file left unchanged: %s', exc)
        return 2
    if getattr(args, 'jeb_path', None):
        settings.jeb_path = args.jeb_path
        settings.validate()
    if args.command == 'analyze':
        if args.index_order is not None:
            settings.index_order = args.index_order
        for key in ('max_index_entries', 'max_index_mib'):
            if getattr(args, key) is not None:
                setattr(settings, key, getattr(args, key))
        settings.validate()
        if args.max_export_mib is not None:
            settings.max_export_mib = args.max_export_mib
            settings.validate()
        if args.jvm_heap_mib is not None:
            settings.jvm_heap_mib = args.jvm_heap_mib
            settings.validate()
        if args.aapt2_path is not None:
            settings.aapt2_path = args.aapt2_path
            settings.validate()
        from analyzer.app.application import AnalysisApplication
        from analyzer.app.project_manager import save_project
        application = AnalysisApplication(settings)
        try:
            result = application.analyze(args.input, Cancellation(),
                        lambda n, s: logging.info('%s%% %s', n, s))
        finally:
            application.backend.close()
        save_project(args.output, result)
        print(f'{len(result.findings)} findings; complete={result.complete}; report={args.output}')
        return 0 if result.complete else 2
    if args.command == 'probe':
        from analyzer.backends.jeb.backend import JebBackend
        try:
            with JebBackend(settings) as backend:
                print(json.dumps(backend.probe(Cancellation()), indent=2))
            return 0
        except Exception as exc:
            print(str(exc))
            return 2
    if args.command == 'inspect':
        from analyzer.backends.jeb.backend import JebBackend
        from analyzer.app.project_manager import write_json
        from dataclasses import asdict
        settings.cache_enabled = False
        with JebBackend(settings) as backend:
            cancel = Cancellation()
            probe_result = backend.probe(cancel)
            program = backend.open_apk(args.input, cancel)
            if args.method not in program.methods:
                raise ValueError('Requested method was not found in indexed method bodies')
            source = backend.get_decompiled_source(args.method, cancel)
            ast = backend.get_ast(args.method, cancel)
            xrefs = backend.get_jeb_xrefs(args.method, cancel)
            report = dict(probe=probe_result, capabilities=backend.capabilities,
                session=backend.session_info, dex_units=program.dex_units,
                method_count=len(program.method_index), indexed_body_count=len(program.methods),
                method=asdict(backend.get_method(args.method)), source=source, ast=ast, xrefs=xrefs,
                callers=backend.get_callers(args.method), callees=backend.get_callees(args.method),
                call_graph=backend.get_call_graph(args.method), diagnostics=program.diagnostics)
            write_json(args.output, report)
            print(f'JEB evidence saved: {args.output}; PID={backend.session.pid}; '
                  f'project_generation={backend.session_info.get("project_generation")}')
        return 0
    from analyzer.gui.main import launch
    return launch(smoke=args.command == 'gui-smoke')


if __name__ == '__main__':
    raise SystemExit(main())
