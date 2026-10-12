"""Read-only saved-project navigation/Qt responsiveness check (no JEB launch)."""
import argparse
import os
import time
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtCore import QTimer
from PySide6.QtGui import QGuiApplication
from analyzer.app.settings import Settings
from analyzer.app.project_manager import open_project, write_json
from analyzer.gui.controllers.workspace import Workspace


def validate(path, app):
    result = open_project(path)
    finding = next(f for f in result.findings if f.location.method in result.program.methods
                   and f.location.offset is not None)
    workspace = Workspace(Settings())
    gaps, last = [], [time.perf_counter()]
    timer = QTimer()
    timer.setInterval(10)
    def tick():
        now = time.perf_counter()
        gaps.append((now - last[0]) * 1000)
        last[0] = now
    timer.timeout.connect(tick)
    try:
        workspace._loaded(result)
        index = next(i for i, item in enumerate(workspace.model.visible) if item.id == finding.id)
        workspace.selectFinding(index)
        workspace.findingLocation()
        assert workspace.evidenceLocation['offset'] == finding.location.offset, workspace.stage
        original = dict(workspace.evidenceLocation)
        timer.start()
        started = time.perf_counter()
        workspace.showTab('Call Graph')
        while workspace.busy:
            app.processEvents()
            if time.perf_counter() - started > 60:
                workspace.cancel()
                raise TimeoutError('Reference query exceeded 60 seconds')
            time.sleep(.001)
        elapsed = time.perf_counter() - started
        timer.stop()
        links = list(workspace.navigationItems)
        assert 'DEX references loaded' in workspace.stage, workspace.stage
        different = next((item for item in links if
                          any(item[k] != original[k] for k in ('method', 'offset', 'unit'))), None)
        if different:
            workspace.navigateLocation(different['method'], different['offset'], different['unit'])
            assert workspace.evidenceLocation['offset'] == different['offset']
            workspace.goBack()
            assert workspace.evidenceLocation == original
        workspace.navigateLocation(original['method'], original['offset'], '__wrong_unit__')
        assert 'refused' in workspace.stage and workspace.evidenceLocation == original
        return dict(project=str(path), finding_id=finding.id, location=original,
                    links=len(links), round_trip=bool(different), query_seconds=round(elapsed, 3),
                    timer_samples=len(gaps), max_timer_gap_ms=round(max(gaps, default=0), 2),
                    scope='One local query; not a UI latency SLA or new APK analysis')
    finally:
        timer.stop()
        workspace.shutdown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('projects', type=Path, nargs='+')
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    app = QGuiApplication([])
    reports = []
    for path in args.projects:
        print('Checking ' + str(path), flush=True)
        reports.append(validate(path, app))
        print(reports[-1], flush=True)
    write_json(args.output, reports)
