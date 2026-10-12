import pytest
from dataclasses import asdict
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.project_manager import save_project, open_project
from analyzer.core.models import Finding, Location, AnalysisResult, Program
from analyzer.core.navigation import bytecode_location
from analyzer.gui.review import review_view
from test_url_validation import guarded, helper_guarded, HELPER, CALLER, add_handler, I


def finding():
    return Finding('r', 'review', '', 'WEBVIEW', location=Location(method=CALLER, offset=3))


def test_review_links_comparisons_branches_handlers_roundtrip(helper_guarded, tmp_path):
    add_handler(helper_guarded.methods[HELPER], 0, 14, [
        I(40, 'move-exception', [9], defs=[9], successors=[41]),
        I(41, 'const/4', [4], defs=[4], literal=0, successors=[42]), I(42, 'return', [4])])
    for method in helper_guarded.methods.values():
        method.unit = 'dex-1'
    f = finding()
    before = asdict(f)
    path = tmp_path / 'review.json'
    save_project(path, AnalysisResult('fixture.apk', 'abc', findings=[f], program=helper_guarded))
    restored = open_project(path)
    summary, text, links = review_view(restored.program, restored.findings[0], Cancellation())
    assert 'EXCEPTION_FLOW_CONSTRAINED' in summary and 'not a safety verdict' in summary
    assert any('exact comparison' in i['label'] for i in links)
    assert any('guard branch' in i['label'] for i in links)
    assert any('accepting successor' in i['label'] for i in links)
    assert any('Handler' in i['label'] and i['offset'] == 40 for i in links)
    for link in links:
        bytecode_location(restored.program, link['method'], link['offset'], link['unit'])
    assert asdict(restored.findings[0]) == before


def test_saved_fake_review_offsets_do_not_create_links(helper_guarded):
    f = finding()
    f.review = {'url_validation': {'status': 'SAFE', 'evidence': [
        dict(method=CALLER, equality_offset=999, branch_offset=999, accepting_successor=999)]}}
    summary, text, links = review_view(helper_guarded, f, Cancellation())
    assert 'SAFE' not in summary and 'saved_candidate_review' in text
    assert links and all(i['offset'] != 999 for i in links)
    assert f.review['url_validation']['status'] == 'SAFE'


def test_legacy_and_invalid_regions_do_not_create_handler_links(helper_guarded):
    helper_guarded.methods[HELPER].exception_status = 'PRESENT'
    helper_guarded.methods[HELPER].exception_regions = [dict(start=0, end=14, handlers=[dict(address=999)])]
    summary, text, links = review_view(helper_guarded, finding(), Cancellation())
    assert 'UNKNOWN' in summary and 'Handler links omitted' in text
    assert all('Handler' not in item['label'] for item in links)


def test_review_link_limit_and_cancel(helper_guarded):
    summary, _, links = review_view(helper_guarded, finding(), Cancellation(), limit=1)
    assert len(links) == 1 and 'truncated' in summary
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        review_view(helper_guarded, finding(), token)


def test_review_missing_method_is_explicit():
    summary, _, links = review_view(Program(), finding(), Cancellation())
    assert 'Method body unavailable' in summary and not links


def test_review_gui_async_navigation_and_note_preservation(helper_guarded):
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtTest import QTest
    from analyzer.gui.controllers.workspace import Workspace
    from analyzer.app.settings import Settings
    import time
    app = QGuiApplication.instance() or QGuiApplication([])
    workspace = Workspace(Settings())
    f = finding()
    try:
        workspace._loaded(AnalysisResult('fixture.apk', 'abc', findings=[f], program=helper_guarded,
                                        notes={f.id: 'keep'}))
        workspace.selectFinding(0)
        workspace.findingLocation()
        origin = dict(workspace.evidenceLocation)
        workspace.showTab('Review')
        deadline = time.monotonic() + 5
        while workspace.busy and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(10)
        assert not workspace.busy and workspace.navigationItems
        item = next(i for i in workspace.navigationItems if 'comparison' in i['label'])
        workspace.navigateLocation(item['method'], item['offset'], item['unit'])
        assert workspace.evidenceLocation['method'] == HELPER
        workspace.goBack()
        assert workspace.evidenceLocation == origin and workspace.analystNote == 'keep'
    finally:
        workspace.shutdown()


def test_review_qml_renders_summary_and_links(helper_guarded):
    import time
    from pathlib import Path
    from PySide6.QtCore import QUrl, qInstallMessageHandler
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtQml import QQmlApplicationEngine
    from PySide6.QtTest import QTest
    from analyzer.gui.controllers.workspace import Workspace
    from analyzer.app.settings import Settings
    import analyzer.gui.main
    app = QGuiApplication.instance() or QGuiApplication([])
    workspace = Workspace(Settings())
    engine = QQmlApplicationEngine()
    messages = []
    previous = qInstallMessageHandler(lambda typ, ctx, msg: messages.append(msg))
    engine.rootContext().setContextProperty('workspace', workspace)
    engine.rootContext().setContextProperty('findingsModel', workspace.model)
    try:
        engine.load(QUrl.fromLocalFile(str(Path(analyzer.gui.main.__file__).parent / 'qml/Main.qml')))
        workspace._loaded(AnalysisResult('SYNTHETIC-REVIEW-FIXTURE.apk', 'abc',
                                        findings=[finding()], program=helper_guarded))
        workspace.selectFinding(0)
        workspace.showTab('Review')
        deadline = time.monotonic() + 5
        while workspace.busy and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(10)
        app.processEvents()
        assert not workspace.busy and engine.rootObjects()
        assert workspace.navigationItems and 'MODELED_EXACT_MATCH' in workspace.reviewSummary
        assert not [m for m in messages if 'Error' in m or 'Unable' in m], messages
        screenshot = engine.rootObjects()[0].grabWindow()
        assert not screenshot.isNull()
        target = Path(__file__).resolve().parents[1] / 'build/gui-review-preview.png'
        target.parent.mkdir(exist_ok=True)
        assert screenshot.save(str(target))
    finally:
        engine.deleteLater()
        app.processEvents()
        qInstallMessageHandler(previous)
        workspace.shutdown()
