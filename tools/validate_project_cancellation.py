"""Observe UI-dispatched cancellation during saved-project load phases."""
import argparse
import json
import os
from pathlib import Path
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtGui import QGuiApplication
from analyzer.app.project_manager import write_json
from analyzer.app.settings import Settings
from analyzer.core.models import AnalysisResult
from analyzer.gui.controllers.workspace import Workspace
from benchmark_field_navigation import measure


def validate(path, app):
    w = Workspace(Settings())
    original = AnalysisResult('existing-session.apk', 'old', notes={'original': 'keep'})
    w._loaded(original)
    expected = (w.content, w.currentTab, dict(w._result.notes), w.projectName)
    rows = []
    try:
        for phase in ('Reading project JSON', 'Validating project schema', 'Building project model'):
            request = []
            def on_change():
                if w.busy and w.stage == phase and not request:
                    request.append(time.perf_counter())
                    w.cancel()
            w.changed.connect(on_change)
            started = time.perf_counter()
            try:
                sample = measure(w, app, lambda: w.reopen(str(path)))
                ended = time.perf_counter()
            finally:
                w.changed.disconnect(on_change)
            assert request, 'Target phase was not observed'
            assert w._result is original and 'cancel' in w.stage.lower(), w.stage
            assert (w.content, w.currentTab, w._result.notes, w.projectName) == expected
            sample.update(phase=phase, request_dispatched_ms=round((request[0] - started) * 1000, 3),
                          request_to_idle_ms=round((ended - request[0]) * 1000, 3))
            rows.append(sample)
            print(path.parent.name, json.dumps(sample, ensure_ascii=True), flush=True)
        return dict(project=str(path.resolve()), phases=rows, original_session_preserved=True,
                    scope='Qt controller/event-loop observation, one trial per delivered progress phase; '
                          'progress delivery can lag worker execution. Native decode is not preemptible. '
                          'No QML rendering or memory measurement in this cancellation run.')
    finally:
        w.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('projects', type=Path, nargs='+')
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() in {p.resolve() for p in args.projects}:
        parser.error('output cannot overwrite an input')
    app = QGuiApplication([])
    reports = []
    for path in args.projects:
        reports.append(validate(path, app))
        write_json(args.output, reports)


if __name__ == '__main__':
    main()
