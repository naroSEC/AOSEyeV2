"""Repeated cancel/reopen in one QML workspace; input projects remain read-only."""
import argparse
import gc
import json
import os
from pathlib import Path
import time
import weakref

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import psutil
from PySide6.QtCore import QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuick import QQuickWindow
from analyzer.app.project_manager import write_json
from analyzer.app.settings import Settings
from analyzer.core.models import AnalysisResult
from analyzer.gui.controllers.workspace import Workspace
from analyzer.gui.fonts import configure_fonts
from benchmark_field_navigation import measure
import analyzer.gui.main


def validate(paths, cycles, output):
    app = QGuiApplication.instance() or QGuiApplication([])
    configure_fonts()
    w = Workspace(Settings())
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty('workspace', w)
    engine.rootContext().setContextProperty('findingsModel', w.model)
    engine.load(QUrl.fromLocalFile(str(Path(analyzer.gui.main.__file__).parent / 'qml/Main.qml')))
    assert engine.rootObjects()
    root = engine.rootObjects()[0]  # Keep the Python wrapper alive throughout the run.
    w._loaded(AnalysisResult('initial-session.apk', 'old'))
    process = psutil.Process()
    def memory():
        info = process.memory_info()
        return dict(rss_mib=round(info.rss / 2**20, 2),
                    lifetime_peak_mib=round(info.peak_wset / 2**20, 2)
                    if hasattr(info, 'peak_wset') else None)
    report = dict(scope='One process, offscreen QML, no JEB launched. RSS before/after explicit gc.collect '
                       'is reported separately; allocator retention is not a live-object leak. '
                       'Only in-memory notes changed; project files are read-only.',
                  cycles=cycles, initial_memory=memory(), rounds=[])
    retired = []
    try:
        for cycle in range(cycles):
            for path in paths:
                original = w._result
                original.notes['benchmark-transient'] = 'preserve through cancellation'
                if w.model.visible:
                    w.selectFinding(0)
                    w.findingLocation()
                state = (w.content, w.currentTab, dict(original.notes), dict(w.evidenceLocation))
                requested = []
                def cancel_at_validation():
                    if w.busy and w.stage == 'Validating project schema' and not requested:
                        requested.append(time.perf_counter())
                        w.cancel()
                w.changed.connect(cancel_at_validation)
                try:
                    cancelled = measure(w, app, lambda: w.reopen(str(path)))
                finally:
                    w.changed.disconnect(cancel_at_validation)
                assert requested and 'cancel' in w.stage.lower(), w.stage
                assert w._result is original
                assert (w.content, w.currentTab, w._result.notes, w.evidenceLocation) == state
                retired.append((weakref.ref(original), weakref.ref(original.program)))
                del original
                cancelled_memory = memory()
                reopened = measure(w, app, lambda: w.reopen(str(path)))
                assert w._result.input_path != 'initial-session.apk' and not w._reopen_pending
                assert 'benchmark-transient' not in w._result.notes
                assert w.app.backend.program is w._result.program
                w.pool.waitForDone()
                app.processEvents()
                before_gc = memory()
                gc.collect()
                app.processEvents()
                alive = sum(ref() is not None for pair in retired for ref in pair)
                assert alive == 0, 'Retired result/program is still retained'
                assert w._job is None and w._finish_callback is None
                row = dict(cycle=cycle + 1, project=str(path.resolve()), cancel=cancelled,
                           after_cancel=cancelled_memory, reopen=reopened,
                           before_gc=before_gc, after_gc=memory(), retired_objects_alive=alive,
                           callbacks_cleared=True, session_preserved_on_cancel=True)
                report['rounds'].append(row)
                write_json(output, report)
                print(json.dumps(row, ensure_ascii=True), flush=True)
        return report
    finally:
        w.shutdown()
        root.close()
        engine.deleteLater()
        app.processEvents()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('projects', type=Path, nargs='+')
    parser.add_argument('--cycles', type=int, default=2)
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.cycles <= 10:
        parser.error('cycles must be 1..10')
    if args.output.resolve() in {p.resolve() for p in args.projects}:
        parser.error('output cannot overwrite an input project')
    validate(args.projects, args.cycles, args.output)


if __name__ == '__main__':
    main()
