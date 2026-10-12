from copy import deepcopy
from pathlib import Path

import pytest
from PySide6.QtCore import QObject, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle

from analyzer.app.settings import Settings
from analyzer.app.project_manager import save_project, open_project
from analyzer.core.models import AnalysisResult
from analyzer.gui.coverage import index_policy_label
from test_dex_browser import browser


@pytest.mark.parametrize('requested,effective', [
    ('native', 'native'), ('manifest-first', 'manifest-first'),
    ('manifest-first', 'native'), (None, None), ('unexpected', '<b>native</b>')])
def test_saved_policy_labels(requested, effective):
    result = AnalysisResult('fixture.apk', '0' * 64)
    result.provenance['requested_index_order'] = requested
    result.program.capabilities['index_order'] = effective
    label = index_policy_label(result)
    assert 'Collection scope is native or not recorded' in label
    if requested in ('native', 'manifest-first'):
        assert f'requested {requested}; effective {effective}' in label
    else:
        assert 'requested unknown (not recorded); effective unknown (not recorded)' in label
    assert '<b>' not in label


def test_setting_save_preserves_result_and_reopen(browser, tmp_path, monkeypatch):
    w, _ = browser
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    w._result.provenance['requested_index_order'] = 'native'
    w._result.program.capabilities['index_order'] = 'native'
    w._result.notes['keep'] = 'review note'
    w._loaded(w._result)
    before, label = deepcopy(w._result.to_dict()), w.coverageLabel
    monkeypatch.setattr(w.app.backend, '_run', lambda *a, **kw: pytest.fail('Must not call JEB'))
    assert w.saveIndexOrder('manifest-first')
    assert Settings.load().index_order == w.indexOrder == 'manifest-first'
    assert w.app.settings is w.settings is w.app.backend.settings
    assert w.coverageLabel == label and w._result.to_dict() == before
    path = tmp_path / 'project.json'
    save_project(path, w._result)
    w._loaded(open_project(path))
    assert w.coverageLabel == label
    assert w.saveIndexOrder('native') and w.indexOrder == 'native'


@pytest.mark.parametrize('mode', ['invalid', 'busy', 'write-error'])
def test_rejected_setting_is_atomic(browser, monkeypatch, mode):
    w, _ = browser
    previous, label = w.settings, w.coverageLabel
    def save(*a, **kw):
        if mode == 'write-error':
            raise OSError('fixture denied')
        pytest.fail('Invalid/busy input must not save')
    monkeypatch.setattr(Settings, 'save', save)
    w._busy = mode == 'busy'
    try:
        assert not w.saveIndexOrder('invalid' if mode == 'invalid' else 'manifest-first')
        assert w.settings is previous and w.app.settings is previous
        assert w.app.backend.settings is previous and w.coverageLabel == label
    finally:
        w._busy = False


def test_qml_policy_dialog_and_saved_banner(browser, tmp_path, monkeypatch):
    w, _ = browser
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    w._result.provenance['requested_index_order'] = 'manifest-first'
    w._result.program.capabilities['index_order'] = 'native (within each JEB unit; not ownership/entrypoint proof)'
    w._loaded(w._result)
    app = QGuiApplication.instance()
    QQuickStyle.setStyle('Basic')
    from analyzer.gui.fonts import configure_fonts
    configure_fonts()
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty('workspace', w)
    engine.rootContext().setContextProperty('findingsModel', w.model)
    import analyzer.gui.main
    engine.load(QUrl.fromLocalFile(str(Path(analyzer.gui.main.__file__).parent / 'qml/Main.qml')))
    assert engine.rootObjects()
    root = engine.rootObjects()[0]
    try:
        dialog = root.findChild(QObject, 'backendSettings')
        combo = root.findChild(QObject, 'indexPolicy')
        button = root.findChild(QObject, 'saveIndexOrder')
        dialog.open()
        app.processEvents()
        assert combo.property('currentText') == 'native'
        combo.setProperty('currentIndex', 1)
        button.clicked.emit()
        app.processEvents()
        assert w.indexOrder == 'manifest-first'
        assert 'requested manifest-first; effective native' in w.coverageLabel
        dialog.open()
        app.processEvents()
        assert combo.property('currentIndex') == 1
        w._busy = True
        w.changed.emit()
        app.processEvents()
        assert not combo.property('enabled') and not button.property('enabled')
        w._busy = False
        w.changed.emit()
        root.setProperty('height', 700)
        app.processEvents()
        assert dialog.property('height') < 700
        scroll = root.findChild(QObject, 'settingsScroll')
        flickable = scroll.property('contentItem')
        assert flickable.property('contentHeight') > flickable.property('height')
        flickable.setProperty('contentY', max(0, flickable.property('contentHeight') - flickable.property('height')))
        app.processEvents()
        output = Path(__file__).resolve().parents[1] / 'build/gui-index-policy.png'
        assert root.grabWindow().save(str(output))
    finally:
        w._busy = False
        root.close()
        engine.deleteLater()
        app.processEvents()
