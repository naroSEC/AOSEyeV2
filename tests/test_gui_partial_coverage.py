from copy import deepcopy
from pathlib import Path

import pytest
from PySide6.QtCore import QObject, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle

from analyzer.gui.coverage import coverage_label
from analyzer.gui.fonts import configure_fonts
from analyzer.core.models import AnalysisResult
from analyzer.app.project_manager import open_project, save_project
from test_dex_browser import browser

DIAGNOSTIC = ('Declaration index budget exhausted; per_kind_limit=1000 encoded_bytes=1 byte_limit=2 '
              'omitted_classes=41032 omitted_fields=165448 omitted_methods=285211; partial analysis')


@pytest.mark.parametrize('case', ['legacy', 'complete', 'budget', 'malformed', 'contradictory'])
def test_coverage_label(case):
    result = AnalysisResult('absent.apk', 'abc', complete=case in ('complete', 'contradictory'))
    if case in ('budget', 'contradictory'):
        result.program.diagnostics = [DIAGNOSTIC]
        result.diagnostics = [DIAGNOSTIC]  # do not double count
    if case == 'malformed':
        result.diagnostics = ['Declaration index budget exhausted; omitted_methods=unknown']
    label = coverage_label(result)
    assert ('PARTIAL ANALYSIS' in label) is (case != 'complete')
    assert 'No match is not proof of absence' in label
    if case in ('budget', 'contradictory'):
        assert 'methods 285211' in label
    elif case != 'complete':
        assert 'totals are not available' in label


def test_missing_navigation_and_search_do_not_fetch_or_mutate(browser, tmp_path, monkeypatch):
    w, wait = browser
    result = w._result
    result.diagnostics.append(DIAGNOSTIC)
    result.notes['saved-note'] = 'keep'
    w._loaded(result)
    before = deepcopy(result.to_dict())
    monkeypatch.setattr(w.app.backend, '_run', lambda *args, **kw: pytest.fail('Saved navigation must not call JEB'))
    w.section('DEX')
    wait()
    w.searchDex('not_present_in_saved_scope')
    wait()
    assert not w.dexItems and 'No matches in the saved index' in w.dexEmptyLabel
    content, location = w.content, deepcopy(w.evidenceLocation)
    w.openDexMethod('Lomitted;->unknown()V')
    assert 'does not prove absence' in w.stage
    assert w.content == content and w.evidenceLocation == location
    assert result.to_dict() == before
    saved = tmp_path / 'partial.json'
    save_project(saved, result)
    label = w.coverageLabel
    w._loaded(open_project(saved))
    assert w.coverageLabel == label and w._result.notes['saved-note'] == 'keep'


def test_real_partial_project_qml_banner(browser):
    w, wait = browser
    path = Path(__file__).resolve().parents[1] / 'build/large-apk-20261004-index1000/amoremall/project.json'
    if not path.exists():
        pytest.skip('Local partial-project validation artifact unavailable')
    original = path.read_bytes()
    result = open_project(path)
    w._loaded(result)
    assert 'methods 285211' in w.coverageLabel and 'bodies 959' in w.coverageLabel
    app = QGuiApplication.instance()
    QQuickStyle.setStyle('Basic')
    configure_fonts()
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty('workspace', w)
    engine.rootContext().setContextProperty('findingsModel', w.model)
    import analyzer.gui.main
    engine.load(QUrl.fromLocalFile(str(Path(analyzer.gui.main.__file__).parent / 'qml/Main.qml')))
    assert engine.rootObjects()
    root = engine.rootObjects()[0]
    try:
        w.section('DEX')
        wait()
        w.searchDex('not_present_in_saved_scope')
        wait()
        app.processEvents()
        banner = root.findChild(QObject, 'coverageBanner')
        notice = root.findChild(QObject, 'dexEmptyNotice')
        assert banner.property('visible') and '285211' in banner.property('text')
        assert notice.property('visible') and 'saved index' in notice.property('text')
        output = path.parents[2] / 'gui-partial-coverage.png'
        assert root.grabWindow().save(str(output))
        assert path.read_bytes() == original and not w._result.complete
    finally:
        root.close()
        engine.deleteLater()
        app.processEvents()
