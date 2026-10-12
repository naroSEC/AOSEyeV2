from zipfile import ZipFile
import pytest
from analyzer.app.application import AnalysisApplication
from analyzer.app.jobs import Cancellation
from analyzer.app.settings import Settings
from analyzer.app.project_manager import save_project, open_project
from analyzer.core.models import Instruction, Program
from conftest import method, SINK


@pytest.mark.parametrize('case', ['read_open', 'read_required', 'path_unknown', 'permission_unknown', 'file_mode', 'custom_call'])
def test_provider_pipeline_evidence_and_roundtrip(tmp_path, case):
    member = 'query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;'
    attrs, children = 'android:writePermission="test.WRITE"', ''
    register, params = 3, list(range(6))
    if case == 'read_required':
        attrs = 'android:readPermission="test.READ"'
    elif case == 'path_unknown':
        children = '<path-permission android:pathPrefix="/x" android:readPermission="test.READ"/>'
    elif case == 'permission_unknown':
        attrs = 'android:readPermission="@string/read"'
    elif case == 'file_mode':
        member = 'openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;'
        register, params = 2, [0, 1, 2]
    elif case == 'custom_call':
        member = 'call(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;'
        register, params = 2, [0, 1, 2, 3]
    signature = 'Ltest/Provider;->' + member
    body = method(signature, [Instruction(0, 'invoke-virtual', [9, register], target=SINK),
                             Instruction(6, 'return-object', [8])], params)
    program = Program(methods={signature: body})
    class Backend:
        def load(self, path, cancel):
            return program
    xml = '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test"><application><provider android:name=".Provider" android:exported="true" ' + attrs + '>' + children + '</provider></application></manifest>'
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w') as archive:
        archive.writestr('AndroidManifest.xml', xml)
    result = AnalysisApplication(Settings(), Backend()).analyze(apk, Cancellation())
    flows = [f for f in result.findings if f.data_flow]
    if case == 'read_required':
        assert not flows
        return
    assert len(flows) == 1
    finding = flows[0]
    certain = case == 'read_open'
    assert finding.verification == ('LIKELY' if certain else 'POTENTIAL')
    assert finding.analysis_level == ('L5' if certain else 'L3')
    assert bool(finding.attack_path) == certain
    reach = finding.review['reachability']
    assert reach['status'] == ('DECLARED_PATH_FOUND' if certain else 'POSSIBLE_ENTRY_PATH_FOUND')
    configuration = reach['paths'][0]['entry_configurations'][0]
    assert bool(configuration['configuration_reasons']) != certain
    assert ('configuration unresolved' in finding.data_flow[0]['label']) != certain
    project = tmp_path / 'project.json'
    save_project(project, result)
    restored = next(f for f in open_project(project).findings if f.data_flow)
    assert restored.review == finding.review and restored.data_flow == finding.data_flow
    from analyzer.gui.review import review_view
    import json
    _, content, _ = review_view(program, restored, Cancellation())
    displayed = json.loads(content)['saved_candidate_review']['reachability']
    assert displayed == reach


def test_reviewer_configuration_output_bound():
    from analyzer.analyzers.verification import CandidateReviewer
    from analyzer.core.models import Method
    sig = 'Ltest/Provider;->call(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;'
    components = [dict(name='test.Provider' + str(n), target='test.Provider', kind='provider',
                       exported=True, enabled=True, permission='', attributes={}) for n in range(25)]
    reviewer = CandidateReviewer(Program(methods={sig: Method(sig)}), dict(components=components))
    path = reviewer.reachability(sig)['paths'][0]
    assert len(path['entry_configurations']) == 20 and path['entry_configurations_truncated']
    assert path['configuration_uncertain']
