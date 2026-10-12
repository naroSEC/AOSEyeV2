"""Read-only saved-project field queries through the real Qt/QML workspace."""
import argparse
from collections import Counter
import os
from pathlib import Path
import platform
import statistics
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from analyzer.app.project_manager import open_project, write_json
from analyzer.app.settings import Settings
from analyzer.gui.controllers.workspace import Workspace
from analyzer.gui.fonts import configure_fonts
from analyzer.core.field_references import _ACCESS
import analyzer.gui.main
import analyzer.gui.controllers.workspace as workspace_module


def measure(workspace, app, action, cancel_after_ms=None):
    gaps = []
    started = last = time.perf_counter()
    cancelled_at = None
    timer, cancel_timer = QTimer(), QTimer()
    timer.setInterval(10)
    cancel_timer.setSingleShot(True)
    def tick():
        nonlocal last
        now = time.perf_counter()
        gaps.append((now - last) * 1000)
        last = now
    def cancel():
        nonlocal cancelled_at
        if workspace.busy:
            cancelled_at = time.perf_counter()
            workspace.cancel()
    timer.timeout.connect(tick)
    cancel_timer.timeout.connect(cancel)
    try:
        timer.start()
        action()
        if cancel_after_ms is not None:
            cancel_timer.start(cancel_after_ms)
        deadline = started + 60
        while workspace.busy:
            app.processEvents()
            if time.perf_counter() > deadline:
                workspace.cancel()
                raise TimeoutError('Field query exceeded 60 seconds')
            time.sleep(.001)
        app.processEvents()
        ended = time.perf_counter()
        tail = (ended - last) * 1000
        return dict(elapsed_ms=round((ended - started) * 1000, 3),
                    timer_samples=len(gaps), max_timer_gap_ms=round(max(gaps + [tail]), 3),
                    median_timer_gap_ms=round(statistics.median(gaps), 3) if gaps else None,
                    cancel_target_ms=cancel_after_ms,
                    cancel_dispatched_ms=round((cancelled_at - started) * 1000, 3) if cancelled_at else None,
                    cancel_to_idle_ms=round((ended - cancelled_at) * 1000, 3) if cancelled_at else None,
                    stage=workspace.stage)
    finally:
        timer.stop()
        cancel_timer.stop()


def validate(path, app, repeats):
    result = open_project(path)
    counts = Counter(i.target for m in result.program.methods.values() for i in m.instructions
                     if i.target and i.opcode in _ACCESS)
    field, count = counts.most_common(1)[0]
    w = Workspace(Settings())
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty('workspace', w)
    engine.rootContext().setContextProperty('findingsModel', w.model)
    engine.load(QUrl.fromLocalFile(str(Path(analyzer.gui.main.__file__).parent / 'qml/Main.qml')))
    if not engine.rootObjects():
        raise RuntimeError('QML failed to load')
    w._loaded(result)
    # Unknown inventory origin is deliberately retained for legacy saved projects.
    w._field_selection = dict(name=field, unit='')
    samples = []
    original_query = workspace_module.field_references
    query_ms = [None]
    def timed_query(*args, **kwargs):
        started = time.perf_counter()
        try:
            return original_query(*args, **kwargs)
        finally:
            query_ms[0] = round((time.perf_counter() - started) * 1000, 3)
    workspace_module.field_references = timed_query
    try:
        for trial in range(repeats):
            for access in ('ALL', 'READ', 'WRITE'):
                action = (lambda: w.showTab('Field XREF')) if not w._field_page else (
                    lambda access=access: w.filterFieldReferences(access))
                sample = measure(w, app, action)
                assert w._field_page is not None and w.fieldFilter == access, w.stage
                sample.update(trial=trial, case=access, total=w._field_page['total'], query_worker_ms=query_ms[0])
                samples.append(sample)
                print(path.parent.name, sample, flush=True)
            before = (w.content, w._field_page, w.navigationItems, dict(w._result.notes))
            sample = measure(w, app, lambda: w.filterFieldReferences('ALL'), cancel_after_ms=10)
            if sample['cancel_dispatched_ms'] is not None:
                assert 'cancel' in w.stage.lower(), w.stage
                assert (w.content, w._field_page, w.navigationItems, w._result.notes) == before
            sample.update(trial=trial, case='CANCEL', query_worker_ms=query_ms[0])
            samples.append(sample)
            print(path.parent.name, sample, flush=True)
        return dict(project=str(path.resolve()), field=field, selected_unit='', operand_count=count,
                    methods=len(result.program.methods),
                    instructions=sum(len(m.instructions) for m in result.program.methods.values()),
                    samples=samples)
    finally:
        workspace_module.field_references = original_query
        engine.deleteLater()
        app.processEvents()
        w.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('projects', type=Path, nargs='+')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error('repeats must be between 1 and 20')
    if args.output.resolve() in {p.resolve() for p in args.projects}:
        parser.error('output must not overwrite an input project')
    app = QGuiApplication.instance() or QGuiApplication([])
    configure_fonts()
    report = dict(python=platform.python_version(), platform=platform.platform(),
                  scope='Local offscreen QML/event-loop observation; excludes project loading; not an SLA, '
                        'physical display input latency, peak memory test or new APK analysis.', projects=[])
    for path in args.projects:
        print('Loading ' + str(path), flush=True)
        report['projects'].append(validate(path, app, args.repeats))
        write_json(args.output, report)


if __name__ == '__main__':
    main()
