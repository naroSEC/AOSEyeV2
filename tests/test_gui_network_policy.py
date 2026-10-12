from copy import deepcopy
import json
from pathlib import Path

import pytest
from PySide6.QtCore import QObject, QMetaObject, Qt, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuick import QQuickWindow
from PySide6.QtQuickControls2 import QQuickStyle

from analyzer.app.project_manager import save_project, open_project
from analyzer.core.models import AnalysisResult, Finding
from analyzer.gui.fonts import configure_fonts
from test_dex_browser import browser


def load_policy(w):
    policy = dict(status='PARSED_DEFAULT_CONFIG', configuration='default-only',
        resource='res/xml/network.xml', reference='@xml/network', base_cleartext_permitted=False,
        domains=[dict(domain='example.com', include_subdomains=True, cleartext_permitted=True)])
    finding = Finding('r', 'Unchanged finding', '', 'NETWORK')
    result = AnalysisResult('missing-original.apk', 'abc', manifest={'network_security_config': policy},
                            findings=[finding], notes={finding.id: 'Keep analyst note'})
    w._loaded(result)
    w.selectFinding(0)
    return result, finding


@pytest.mark.parametrize('host, status', [('api.example.com', 'PERMITTED'), ('else.test', 'NOT_PERMITTED'),
    ('badexample.com', 'NOT_PERMITTED'), ('https://example.com', 'UNKNOWN')])
def test_offline_host_lookup_preserves_analysis(browser, tmp_path, monkeypatch, host, status):
    w, _ = browser
    result, finding = load_policy(w)
    before = deepcopy(result.to_dict())
    monkeypatch.setattr(w.app.backend, '_run', lambda *a, **kw: pytest.fail('Offline lookup must not use JEB'))
    w.section('Network Policy')
    w.queryNetworkHost(host)
    value = json.loads(w.content)
    assert value['selection']['status'] == status
    assert value['selection']['configuration'] == 'default-only'
    assert value['resource'] == 'res/xml/network.xml'
    assert w._selected is finding and w.analystNote == 'Keep analyst note'
    assert result.to_dict() == before
    w.showNetworkPolicy()
    assert json.loads(w.content)['policy'] == result.manifest['network_security_config']
    project = tmp_path / 'saved.json'
    save_project(project, result)
    w._loaded(open_project(project))
    w.section('Network Policy')
    w.queryNetworkHost(host)
    assert json.loads(w.content)['selection']['status'] == status


def test_busy_absent_and_wrong_section(browser):
    w, _ = browser
    w.section('Network Policy')
    w.queryNetworkHost('example.com')
    assert json.loads(w.content)['selection']['status'] == 'UNKNOWN'
    original = w.content
    w._busy = True
    try:
        w.queryNetworkHost('other.test')
        w.showNetworkPolicy()
        assert w.content == original
    finally:
        w._busy = False
    w.section('Overview')
    original = w.content
    w.queryNetworkHost('example.com')
    assert w.content == original and w.currentTab == 'Evidence'


def test_qml_host_input_button_wiring_and_render(browser):
    w, _ = browser
    load_policy(w)
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
        w.section('Network Policy')
        app.processEvents()
        field = root.findChild(QObject, 'networkHost')
        button = root.findChild(QObject, 'queryNetworkHost')
        assert field and button and field.property('visible') and button.property('enabled')
        field.setProperty('text', 'api.example.com')
        assert QMetaObject.invokeMethod(button, 'clicked', Qt.DirectConnection)
        app.processEvents()
        assert json.loads(w.content)['selection']['status'] == 'PERMITTED'
        image = root.grabWindow()
        assert not image.isNull()
        output = Path(__file__).resolve().parents[1] / 'build/gui-network-policy.png'
        output.parent.mkdir(exist_ok=True)
        assert image.save(str(output))
        dialog = root.findChild(QObject, 'backendSettings')
        tool_path = root.findChild(QObject, 'aapt2Path')
        save_tool = root.findChild(QObject, 'saveAapt2')
        assert dialog and tool_path and save_tool
        assert QMetaObject.invokeMethod(dialog, 'open', Qt.DirectConnection)
        tool_path.setProperty('text', 'relative-not-allowed.exe')
        assert QMetaObject.invokeMethod(save_tool, 'clicked', Qt.DirectConnection)
        app.processEvents()
        assert 'unchanged' in w.stage and dialog.property('visible')
        assert root.grabWindow().save(str(output.with_name('gui-aapt2-settings.png')))
    finally:
        root.close()
        engine.deleteLater()
        app.processEvents()
