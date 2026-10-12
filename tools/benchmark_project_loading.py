"""Isolated-process project loading and 300 verified-link QML benchmark."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')


def child(path, output):
    import psutil
    from PySide6.QtCore import QTimer, QUrl, QObject, QMetaObject, Q_ARG
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtQml import QQmlApplicationEngine
    from PySide6.QtQuick import QQuickItem
    from analyzer.app.project_manager import write_json
    from analyzer.app.settings import Settings
    from analyzer.core.field_references import _ACCESS
    from analyzer.core.navigation import bytecode_location
    from analyzer.gui.controllers.workspace import Workspace
    from analyzer.gui.fonts import configure_fonts
    import analyzer.gui.main

    process = psutil.Process()
    app = QGuiApplication([])
    configure_fonts()
    w = Workspace(Settings())
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty('workspace', w)
    engine.rootContext().setContextProperty('findingsModel', w.model)
    engine.load(QUrl.fromLocalFile(str(Path(analyzer.gui.main.__file__).parent / 'qml/Main.qml')))
    assert engine.rootObjects()
    root = engine.rootObjects()[0]
    app.processEvents()

    def memory():
        info = process.memory_info()
        return dict(rss_mib=round(info.rss / 2**20, 2),
                    process_peak_rss_mib=round(info.peak_wset / 2**20, 2)
                    if hasattr(info, 'peak_wset') else None)

    def measure(action):
        gaps = []
        started = last = time.perf_counter()
        before = memory()
        timer = QTimer()
        timer.setInterval(10)
        def tick():
            nonlocal last
            now = time.perf_counter()
            gaps.append((now - last) * 1000)
            last = now
        timer.timeout.connect(tick)
        try:
            timer.start()
            action()
            while w.busy:
                app.processEvents()
                if time.perf_counter() - started > 180:
                    raise TimeoutError('Job exceeded 180 seconds')
                time.sleep(.001)
            app.processEvents()
            ended = time.perf_counter()
            return dict(elapsed_ms=round((ended - started) * 1000, 3),
                        timer_samples=len(gaps),
                        max_timer_gap_ms=round(max(gaps + [(ended - last) * 1000]), 3),
                        before=before, after=memory(), stage=w.stage)
        finally:
            timer.stop()

    report = dict(project=str(path.resolve()), project_bytes=path.stat().st_size,
                  python=platform.python_version(), platform=platform.platform(),
                  scope='Fresh process, offscreen QML; OS process-lifetime peak working set includes Qt. '
                        'No physical input latency SLA, no new APK analysis; input read only.')
    try:
        report['load'] = measure(lambda: w.reopen(str(path)))
        assert w._result is not None, w.stage
        print('Loaded', path.parent.name, json.dumps(report['load'], ensure_ascii=True), flush=True)
        p = w._result.program
        counts = Counter((m.unit, i.target) for m in p.methods.values() if m.unit
                         for i in m.instructions if i.target and i.opcode in _ACCESS)
        (unit, field), count = counts.most_common(1)[0]
        assert count >= 300, 'Project does not provide 300 known-unit operand matches'
        report.update(field=field, unit=unit, operand_count=count,
                      unit_basis='Observed caller method.unit; no field declaration origin inferred')
        w._field_selection = dict(name=field, unit=unit)
        report['links'] = []
        for _ in range(3):
            sample = measure(lambda: w.showTab('Field XREF'))
            assert len(w.navigationItems) == 300, w.stage
            sample['links'] = len(w.navigationItems)
            report['links'].append(sample)
            print('Links', path.parent.name, json.dumps(sample, ensure_ascii=True), flush=True)
        for item in w.navigationItems:
            bytecode_location(p, item['method'], item['offset'], item['unit'])
        view = root.findChild(QQuickItem, 'referenceList')
        assert view is not None
        def scroll():
            assert QMetaObject.invokeMethod(view, 'positionViewAtIndex', Q_ARG(int, 299), Q_ARG(int, 2))
        report['scroll_to_last'] = measure(scroll)
        assert view.property('contentY') > 0, 'Reference list did not scroll'
        item = w.navigationItems[-1]
        report['navigate_last'] = measure(lambda: w.navigateLocation(item['method'], item['offset'], item['unit']))
        assert w.evidenceLocation == {key: item[key] for key in ('method', 'offset', 'unit')}
        report['verified_locations'] = 300
        write_json(output, report)
    finally:
        w.shutdown()
        engine.deleteLater()
        app.processEvents()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('projects', type=Path, nargs='+')
    parser.add_argument('-o', '--output', type=Path, required=True)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.output.resolve() in {p.resolve() for p in args.projects}:
        parser.error('output cannot overwrite an input')
    if args.child:
        if len(args.projects) != 1:
            parser.error('child requires one project')
        child(args.projects[0], args.output)
        return
    from analyzer.app.project_manager import write_json
    reports = []
    for index, project in enumerate(args.projects):
        detail = args.output.with_name(args.output.stem + f'-{index + 1}.json')
        if detail.resolve() in {p.resolve() for p in args.projects}:
            parser.error('detail output cannot overwrite an input')
        subprocess.run([sys.executable, str(Path(__file__).resolve()), '--child', str(project),
                        '-o', str(detail)], check=True, timeout=240)
        reports.append(json.loads(detail.read_text(encoding='utf-8')))
        write_json(args.output, reports)


if __name__ == '__main__':
    main()
