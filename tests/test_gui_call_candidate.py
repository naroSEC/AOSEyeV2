import os
from copy import deepcopy
from pathlib import Path

import pytest

from analyzer.app.jobs import Cancelled, Cancellation
from analyzer.core.models import AnalysisResult, Program, Method, Instruction
from test_dex_browser import browser


def prepare(w):
    caller = 'Lcaller;->run()V'
    w._result.program = Program(methods={caller: Method(caller, unit='u', instructions=[
        Instruction(0, 'invoke-static', target='Ltarget;->run()V')])})
    w._result.notes['keep'] = 'review note'
    w._loaded(w._result)
    w.section('Diagnostics')
    w.navigateLocation(caller, 0, 'u')
    return caller


@pytest.mark.parametrize('mode', ['success', 'budget', 'error', 'cancel', 'late_cancel'])
def test_preview_preserves_saved_view(browser, monkeypatch, mode):
    w, wait = browser
    caller = prepare(w)
    before, content, location = deepcopy(w._result.to_dict()), w.content, deepcopy(w.evidenceLocation)
    opened = []
    w.candidateReady.connect(lambda: opened.append(True))
    def preview(signature, offset, token, max_bytes):
        assert signature == caller and offset == 0 and max_bytes == 262144
        if mode == 'error':
            raise ValueError('fixture error')
        if mode == 'cancel':
            raise Cancelled()
        if mode == 'late_cancel':
            token.cancel()
        return dict(status='BUDGET_EXCEEDED' if mode == 'budget' else 'CANDIDATE',
                    method=dict(signature='Ltarget;->run()V', unit='u'))
    monkeypatch.setattr(w.app.backend, 'preview_call_target', preview)
    w.previewCallTarget(256)
    wait()
    assert w._result.to_dict() == before and w.content == content and w.evidenceLocation == location
    assert bool(opened) == (mode == 'success')
    if mode == 'success':
        assert 'not merged or reanalyzed' in w.candidateText
        w.discardCandidate()
    assert w.candidateText == ''


def test_stale_preview_and_invalid_budget(browser, monkeypatch):
    w, _ = browser
    prepare(w)
    pending = []
    monkeypatch.setattr(w, '_start', lambda work, done: pending.append((work, done)))
    w.previewCallTarget(0)
    assert not pending
    w.previewCallTarget(256)
    w._loaded(AnalysisResult('new.apk', '0' * 64))
    with pytest.raises(ValueError, match='Stale'):
        pending[0][1](dict(status='CANDIDATE'))
    assert w.candidateText == ''


def test_qml_preview_and_discard(browser, monkeypatch):
    from PySide6.QtCore import QObject, QUrl
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtQml import QQmlApplicationEngine
    from PySide6.QtQuickControls2 import QQuickStyle
    from analyzer.gui.fonts import configure_fonts
    import analyzer.gui.main
    w, wait = browser
    prepare(w)
    monkeypatch.setattr(w.app.backend, 'preview_call_target', lambda *a, **kw: dict(status='CANDIDATE',
        method=dict(signature='Ltarget;->run()V', unit='u', instructions=[dict(offset=0, opcode='return-void')]),
        byte_limit=262144, encoded_bytes=100))
    app = QGuiApplication.instance()
    QQuickStyle.setStyle('Basic')
    configure_fonts()
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty('workspace', w)
    engine.rootContext().setContextProperty('findingsModel', w.model)
    engine.load(QUrl.fromLocalFile(str(Path(analyzer.gui.main.__file__).parent / 'qml/Main.qml')))
    assert engine.rootObjects()
    root = engine.rootObjects()[0]
    try:
        button = root.findChild(QObject, 'previewCallTarget')
        assert button.property('visible')
        button.clicked.emit()
        wait()
        app.processEvents()
        dialog = root.findChild(QObject, 'candidateDialog')
        assert dialog.property('visible')
        assert 'not merged' in root.findChild(QObject, 'candidateContent').property('text')
        assert root.grabWindow().save(str(Path(__file__).resolve().parents[1] / 'build/gui-call-candidate.png'))
        dialog.close()
        app.processEvents()
        assert w.candidateText == ''
    finally:
        root.close()
        engine.deleteLater()
        app.processEvents()


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_live_gui_candidate(browser, tmp_path):
    w, wait = browser
    path = Path(__file__).resolve().parents[1] / 'build/fixtures/flow-fixture.apk'
    w.app.backend.settings.jvm_heap_mib = 1024
    w.app.backend.settings.cache_enabled = False
    program = w.app.backend.load(path, Cancellation())
    sites = [(m, i) for m in program.methods.values() for i in m.instructions
             if i.opcode in ('invoke-static', 'invoke-direct') and i.target in program.methods and i.target != m.signature]
    assert sites
    caller, ins = sites[0]
    program.methods.pop(ins.target)
    result = AnalysisResult(str(path), w.app.backend.input_sha256, program=program,
                            provenance={'version': w.app.backend.version}, notes={'keep': 'analyst note'})
    w._loaded(result)
    w.section('Diagnostics')
    w.navigateLocation(caller.signature, ins.offset, caller.unit)
    before = deepcopy(result.to_dict())
    w.previewCallTarget(256)
    wait()
    assert ins.target in w.candidateText
    assert result.to_dict() == before and ins.target not in result.program.methods
    from analyzer.app.candidate_artifact import open_candidate
    output = tmp_path / 'live.candidate.json'
    assert w.exportCandidate(str(output))
    artifact = open_candidate(output)
    assert artifact['candidate']['method']['signature'] == ins.target
    assert artifact['candidate']['input_sha256'] == result.sha256
    assert artifact['candidate']['caller_unit'] == caller.unit
    assert result.to_dict() == before
    w.analyzeCandidate()
    wait()
    assert w._result is not result and ins.target in w._result.program.methods
    assert result.to_dict() == before and w._result.notes == result.notes
    assert w._result.provenance['candidate_expansions'][0]['target'] == ins.target
    assert not w._result.complete
