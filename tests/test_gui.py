import os
import pytest
import time
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtCore import Qt, QUrl, qInstallMessageHandler
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle
from pathlib import Path
from analyzer.gui.controllers.workspace import Workspace
from analyzer.gui.models.findings import FindingsModel
from analyzer.core.models import Finding
from analyzer.core.models import AnalysisResult
from analyzer.core.dataflow import FlowEngine
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from conftest import ENTRY
from analyzer.gui.fonts import configure_fonts
from analyzer.app.settings import Settings


def test_model_filtering():
    model = FindingsModel()
    model.reset([Finding('r1', 'External URL', '', 'WEBVIEW', severity='HIGH'),
                 Finding('r2', 'Exported service', '', 'COMPONENT')])
    model.reset(query='external', severity='HIGH')
    assert model.rowCount() == 1
    assert model.data(model.index(0), Qt.UserRole + 1) == 'External URL'
    model.reset(query='missing')
    assert model.rowCount() == 0


def test_unconfigured_startup_requests_path_without_background_probe(monkeypatch):
    monkeypatch.delenv('AOSEYE_JEB_PATH', raising=False)
    workspace = Workspace(Settings())
    try:
        workspace.checkBackend()
        assert workspace._backend_status == 'Not configured'
        assert 'JEB settings' in workspace.stage
        assert not workspace.busy
        assert workspace.app.backend.session.process is None
    finally:
        workspace.shutdown()


def test_boundary_inventory_view_discloses_uncertainty():
    workspace = Workspace()
    try:
        workspace._loaded(AnalysisResult('fixture.apk', '0' * 64, provenance={
            'flow_coverage': {'boundaries': [dict(kind='ICC', status='UNRESOLVED')]}}))
        workspace.section('Boundaries')
        assert 'UNRESOLVED' in workspace.content and 'not proof of execution' in workspace.content
    finally:
        workspace.shutdown()


def test_candidate_review_tab():
    from PySide6.QtTest import QTest
    app = QGuiApplication.instance() or QGuiApplication([])
    workspace = Workspace()
    try:
        finding = Finding('test', 'Review candidate', '', 'WEBVIEW',
                          review={'reachability': {'status': 'NO_MODELED_PATH_FOUND'}})
        workspace._loaded(AnalysisResult('fixture.apk', '0' * 64, findings=[finding]))
        workspace.selectFinding(0)
        workspace.showTab('Review')
        deadline = time.monotonic() + 5
        while workspace.busy and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(10)
        assert not workspace.busy
        assert 'NO_MODELED_PATH_FOUND' in workspace.content
    finally:
        workspace.shutdown()


def test_invalid_reopen_preserves_session_and_notes(tmp_path):
    from PySide6.QtTest import QTest
    app = QGuiApplication.instance() or QGuiApplication([])
    workspace = Workspace(Settings())
    finding = Finding('r', 'Original finding', '', 'WEBVIEW')
    result = AnalysisResult('old.apk', 'old', findings=[finding], notes={finding.id: 'keep me'})
    path = tmp_path / 'invalid.json'
    path.write_text('{"schema_version":1,"input_path":7,"sha256":"bad"}')
    try:
        workspace._loaded(result)
        workspace.selectFinding(0)
        workspace.reopen(str(path))
        deadline = time.monotonic() + 5
        while workspace.busy and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(10)
        assert not workspace.busy
        assert workspace._result is result and workspace._selected is finding
        assert workspace.projectName == 'old.apk'
        assert workspace.analystNote == 'keep me' and workspace.findingCount == 1
        assert 'expected str' in workspace.stage
        workspace.showTab('Evidence')
        assert workspace._selected is finding
    finally:
        workspace.shutdown()


def test_failed_settings_save_does_not_mutate_workspace(monkeypatch):
    workspace = Workspace(Settings())
    original = workspace.settings
    def fail(*args):
        raise OSError('disk full')
    monkeypatch.setattr(Settings, 'save', fail)
    try:
        workspace.probe('C:/new-jeb')
        assert workspace.settings is original
        assert 'Settings were not changed' in workspace.stage
        assert not workspace.busy
    finally:
        workspace.shutdown()


def test_navigation_history_rejection_and_async_references(flow_program):
    from PySide6.QtTest import QTest
    from conftest import HELPER
    from analyzer.core.models import Location
    app = QGuiApplication.instance() or QGuiApplication([])
    workspace = Workspace(Settings())
    finding = Finding('r', 'Flow', '', 'WEBVIEW', location=Location(method=HELPER, offset=0))
    try:
        workspace._loaded(AnalysisResult('app.apk', 'abc', findings=[finding], program=flow_program))
        workspace.selectFinding(0)
        workspace.findingLocation()
        workspace.navigateLocation(ENTRY, 20, '')
        assert '>>> 0014' in workspace.content and workspace.canGoBack
        old_content = workspace.content
        workspace.navigateLocation(ENTRY, 21, '')
        assert workspace.content == old_content and 'refused' in workspace.stage
        workspace.goBack()
        assert workspace.evidenceLocation['method'] == HELPER
        workspace.showTab('XREF')
        deadline = time.monotonic() + 5
        while workspace.busy and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(10)
        assert not workspace.busy
        assert workspace.currentTab == 'XREF'
        assert workspace.navigationItems[0]['method'] == ENTRY
        assert 'raw_declared_target' in workspace.content
        item = workspace.navigationItems[0]
        workspace.navigateLocation(item['method'], item['offset'], item['unit'])
        assert workspace.evidenceLocation['offset'] == 20
    finally:
        workspace.shutdown()


def test_qml_loads_without_errors(flow_program):
    QQuickStyle.setStyle('Basic')
    app = QGuiApplication.instance() or QGuiApplication([])
    configure_fonts()
    errors = []
    previous = qInstallMessageHandler(lambda typ, ctx, msg: errors.append(msg))
    engine = QQmlApplicationEngine()
    workspace = Workspace()
    engine.rootContext().setContextProperty('workspace', workspace)
    engine.rootContext().setContextProperty('findingsModel', workspace.model)
    import analyzer.gui.main
    engine.load(QUrl.fromLocalFile(str(Path(analyzer.gui.main.__file__).parent / 'qml/Main.qml')))
    findings, _ = FlowEngine(RuleRegistry()).analyze(flow_program, {ENTRY}, Cancellation())
    result = AnalysisResult('SYNTHETIC-FLOW-FIXTURE.apk', '0' * 64, findings=findings, program=flow_program,
                            diagnostics=['Synthetic normalized fixture; not a real APK analysis'])
    workspace._loaded(result)
    workspace.selectFinding(0)
    workspace.showTab('Data Flow')
    app.processEvents()
    try:
        assert engine.rootObjects(), errors
        assert not [e for e in errors if 'Error' in e or 'Unable' in e], errors
        image = engine.rootObjects()[0].grabWindow()
        assert not image.isNull()
        preview = Path(__file__).resolve().parents[1] / 'build/gui-preview.png'
        preview.parent.mkdir(exist_ok=True)
        assert image.save(str(preview))
    finally:
        engine.deleteLater()
        app.processEvents()
        qInstallMessageHandler(previous)
        workspace.shutdown()


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Set AOSEYE_RUN_JEB=1 for live GUI jobs')
def test_live_gui_jobs_share_backend(tmp_path, monkeypatch):
    from PySide6.QtTest import QTest
    app = QGuiApplication.instance() or QGuiApplication([])
    configure_fonts()
    fixture = Path(__file__).resolve().parents[1] / 'build/fixtures/flow-fixture.apk'
    if not fixture.exists():
        pytest.skip('Run python tools/build_fixture.py first')
    workspace = Workspace(Settings(cache_enabled=False))
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty('workspace', workspace)
    engine.rootContext().setContextProperty('findingsModel', workspace.model)
    import analyzer.gui.main
    engine.load(QUrl.fromLocalFile(str(Path(analyzer.gui.main.__file__).parent / 'qml/Main.qml')))
    assert engine.rootObjects()
    def wait_job():
        deadline = time.monotonic() + 40
        while workspace.busy and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(10)
        assert not workspace.busy, workspace.stage
    try:
        workspace.checkBackend()
        wait_job()
        assert workspace.backendStatus.startswith('Connected')
        process = workspace.app.backend.session.process
        workspace.analyze(str(fixture))
        wait_job()
        assert workspace._result is not None, workspace.stage
        assert workspace._result.complete, workspace._result.diagnostics
        index = next(i for i, f in enumerate(workspace.model.visible) if f.analysis_level == 'L5')
        workspace.selectFinding(index)
        result, selected = workspace._result, workspace._selected
        result.notes[selected.id] = 'Preserve through reconnect'
        workspace.findingLocation()
        snapshot = (workspace.content, dict(workspace.evidenceLocation), list(workspace._history))
        valid_home = workspace.jebPath
        workspace.probe(str(tmp_path / 'missing-jeb'))
        wait_job()
        assert workspace.backendStatus == 'Unavailable'
        assert process.poll() is not None
        assert (workspace.content, workspace.evidenceLocation, workspace._history) == snapshot
        assert workspace._result is result and workspace.analystNote == 'Preserve through reconnect'
        workspace.probe(valid_home)
        wait_job()
        assert workspace.backendStatus.startswith('Connected')
        assert workspace._result is result and workspace._selected is selected
        assert workspace.analystNote == 'Preserve through reconnect'
        assert (workspace.content, workspace.evidenceLocation, workspace._history) == snapshot
        assert workspace.app.backend.program is result.program
        assert Settings.load().jeb_path == valid_home
        process = workspace.app.backend.session.process
        # Mutate only a disposable copy, never the fixture or a user's APK.
        disposable = tmp_path / 'original-copy.apk'
        saved_input_path = result.input_path
        result.input_path = str(disposable)
        for state in ('missing', 'changed'):
            if state == 'changed':
                disposable.write_bytes(b'not the analyzed APK')
            for tab in ('AST', 'JEB XREF', 'Code'):
                previous_tab = workspace.currentTab
                workspace.decompile() if tab == 'Code' else workspace.showTab(tab)
                wait_job()
                assert 'missing or changed' in workspace.stage
                assert workspace.currentTab == previous_tab
                assert (workspace.content, workspace.evidenceLocation, workspace._history) == snapshot
                assert workspace.analystNote == 'Preserve through reconnect'
                assert workspace.app.backend.session.process is process
        disposable.write_bytes(fixture.read_bytes())
        workspace.showTab('AST')
        wait_job()
        assert '"nodes"' in workspace.content
        result.input_path = saved_input_path
        workspace.showTab('AST')
        wait_job()
        assert '"nodes"' in workspace.content, workspace.stage
        workspace.showTab('JEB XREF')
        wait_job()
        assert 'getCrossReferences' in workspace.content, workspace.stage
        # Exercise a known positive vendor reference and return to its requested method.
        helper = 'Ltest/Navigation;->open(Ljava/lang/String;)V'
        workspace.navigateMethod(helper)
        origin = dict(workspace.evidenceLocation)
        workspace.showTab('JEB XREF')
        wait_job()
        assert len(workspace.navigationItems) == 2, workspace.content
        workspace.XREF_PAGE_SIZE = 1
        workspace.showTab('JEB XREF')
        wait_job()
        assert workspace.xrefPageLabel == '1–1 / 2 references'
        assert workspace.xrefHasNext and not workspace.xrefHasPrevious
        workspace.nextXrefPage()
        wait_job()
        assert workspace.xrefPageLabel == '2–2 / 2 references'
        assert workspace.xrefHasPrevious and not workspace.xrefHasNext
        app.processEvents()
        assert engine.rootObjects()[0].grabWindow().save(str(fixture.parents[1] / 'gui-xref-pagination.png'))
        workspace.previousXrefPage()
        wait_job()
        assert workspace.xrefPageLabel == '1–1 / 2 references'
        item = workspace.navigationItems[0]
        workspace.navigateLocation(item['method'], item['offset'], item['unit'])
        assert workspace.evidenceLocation['offset'] == item['offset']
        workspace.goBack()
        assert workspace.evidenceLocation == origin
        workspace.decompile()
        wait_job()
        assert 'loadUrl' in workspace.content, workspace.stage
        assert workspace.app.backend.session.process is process
        workspace.section('DEX')
        wait_job()
        workspace.openDexClass('Ltest/Navigation;')
        wait_job()
        workspace.openDexMethod(helper)
        assert workspace._selected is None
        workspace.showTab('AST')
        wait_job()
        assert '"nodes"' in workspace.content
        workspace.showTab('JEB XREF')
        wait_job()
        assert workspace.xrefHasNext
        workspace.decompile()
        wait_job()
        assert 'loadUrl' in workspace.content
        app.processEvents()
        assert engine.rootObjects()[0].grabWindow().save(str(fixture.parents[1] / 'gui-dex-browser.png'))
        field_index = next(i for i, row in enumerate(workspace.dexItems) if row['kind'] == 'field' and '->last:' in row['name'])
        workspace.openDexEntry(field_index)
        wait_job()
        import json
        refs = json.loads(workspace.content)
        assert {r['access'] for r in refs['items']} == {'READ', 'WRITE'}
        assert len(workspace.navigationItems) == 2
        workspace.FIELD_PAGE_SIZE = 1
        workspace.showTab('Field XREF')
        wait_job()
        assert workspace.fieldHasNext
        workspace.nextFieldPage()
        wait_job()
        assert workspace.fieldPageLabel == '2–2 / 2 operands'
        workspace.previousFieldPage()
        wait_job()
        workspace.filterFieldReferences('READ')
        wait_job()
        assert workspace.fieldPageLabel == '1–1 / 1 operands'
        assert 'Field READ' in workspace.navigationItems[0]['label']
        workspace.filterFieldReferences('WRITE')
        wait_job()
        assert 'Field WRITE' in workspace.navigationItems[0]['label']
        app.processEvents()
        assert engine.rootObjects()[0].grabWindow().save(str(fixture.parents[1] / 'gui-field-xref.png'))
        link = workspace.navigationItems[0]
        workspace.navigateLocation(link['method'], link['offset'], link['unit'])
        assert workspace.evidenceLocation['offset'] == link['offset']
        app.processEvents()
        preview = fixture.parents[1] / 'gui-jeb-preview.png'
        assert engine.rootObjects()[0].grabWindow().save(str(preview))
    finally:
        engine.deleteLater()
        app.processEvents()
        workspace.shutdown()
    assert process.poll() == 0
