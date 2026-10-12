from copy import deepcopy

import pytest

from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.core.call_coverage import call_target_page, call_coverage
from analyzer.core.models import Program, Method, Instruction
from test_dex_browser import browser


def large_program():
    method = Method('Lcaller;->run()V', unit='u', instructions=[
        Instruction(i, 'invoke-static', target='Lmissing;->run()V') for i in range(305)])
    return Program(methods={method.signature: method})


def test_page_partition_and_counters():
    program = large_program()
    before = deepcopy(program)
    first = call_target_page(program)
    last = call_target_page(program, offset=300)
    assert first['total'] == 305 and len(first['items']) == 100 and first['has_more']
    assert len(last['items']) == 5 and not last['has_more']
    assert last['items'][0]['offset'] == 300
    assert first['total'] == call_coverage(program)['counts']['unindexed_target']
    assert call_target_page(program, 'ambiguous_units')['total'] == 0
    assert not call_target_page(program, offset=400)['items']
    assert program == before


def test_unknown_unit_and_duplicate_offsets_not_linked():
    program = large_program()
    method = next(iter(program.methods.values()))
    method.unit = ''
    assert not call_target_page(program)['items'][0]['navigation_allowed']
    method.unit = 'u'
    method.instructions[1].offset = 0
    rows = call_target_page(program)['items']
    assert not rows[0]['navigation_allowed'] and not rows[1]['navigation_allowed']
    assert rows[2]['navigation_allowed']


@pytest.mark.parametrize('kwargs', [{'offset': -1}, {'limit': 301}, {'status': 'bad'}, {'offset': True}])
def test_invalid_page(kwargs):
    with pytest.raises(ValueError):
        call_target_page(Program(), **kwargs)


def test_query_cancellation():
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        call_target_page(large_program(), cancel=token)


def test_gui_pages_caller_navigation_and_cancel(browser, monkeypatch):
    w, wait = browser
    w._result.program = large_program()
    w._result.notes['keep'] = 'unchanged'
    w._loaded(w._result)
    before = deepcopy(w._result.to_dict())
    monkeypatch.setattr(w.app.backend, '_run', lambda *a, **kw: pytest.fail('No live JEB request'))
    w.section('Diagnostics')
    w.queryCallTargets('UNAVAILABLE', 0)
    wait()
    assert w.callTargetPage['total'] == 305 and len(w.navigationItems) == 100
    row = w.navigationItems[0]
    w.navigateLocation(row['method'], row['offset'], row['unit'])
    assert w.currentTab == 'Bytecode' and w.evidenceLocation['offset'] == 0
    w.queryCallTargets('unindexed_target', 300)
    wait()
    assert len(w.navigationItems) == 5
    content, links, page = w.content, deepcopy(w.navigationItems), deepcopy(w.callTargetPage)
    w.queryCallTargets('invalid', 0)
    wait()
    assert w.content == content and w.navigationItems == links and w.callTargetPage == page
    # Late cancellation must not replace the prior page after worker success.
    w.queryCallTargets('ALL', 0)
    w.cancel()
    wait()
    assert w.content == content and w.callTargetPage == page
    assert w._result.to_dict() == before
    # Render the actual new controls and exercise their QML wiring.
    from pathlib import Path
    from PySide6.QtCore import QObject, QUrl
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtQml import QQmlApplicationEngine
    from PySide6.QtQuickControls2 import QQuickStyle
    from analyzer.gui.fonts import configure_fonts
    import analyzer.gui.main
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
        button = root.findChild(QObject, 'queryCallTargets')
        assert button.property('visible')
        button.clicked.emit()
        wait()
        assert w.callTargetPage['offset'] == 0
        assert w.callTargetPage['status'] == 'UNAVAILABLE'
        app.processEvents()
        output = Path(__file__).resolve().parents[1] / 'build/gui-call-targets.png'
        assert root.grabWindow().save(str(output))
    finally:
        root.close()
        engine.deleteLater()
        app.processEvents()


def test_late_page_rejected_on_new_result(browser, monkeypatch):
    w, _ = browser
    w.section('Diagnostics')
    pending = []
    monkeypatch.setattr(w, '_start', lambda work, done: pending.append((work, done)))
    w.queryCallTargets('ALL', 0)
    page = pending[0][0](None)
    from analyzer.core.models import AnalysisResult
    w._loaded(AnalysisResult('new.apk', '0' * 64))
    content = w.content
    with pytest.raises(ValueError, match='Stale'):
        pending[0][1](page)
    assert w.content == content and w.callTargetPage == {}
