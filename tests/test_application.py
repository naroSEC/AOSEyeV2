from dataclasses import asdict
import json
from zipfile import ZipFile, ZIP_DEFLATED
import pytest
from analyzer.app.application import AnalysisApplication
from analyzer.app.jobs import Cancellation
from analyzer.app.settings import Settings
from analyzer.app.project_manager import save_project, open_project
from analyzer.analyzers.apk import inspect_apk
from analyzer.backends.base import BackendError
from analyzer.core.models import AnalysisResult
from analyzer.core.rules.registry import RuleRegistry
from test_manifest import manifest


class FixtureBackend:
    def __init__(self, program):
        self.program = program

    def load(self, path, cancel):
        return self.program


def test_apk_pipeline_and_roundtrip(tmp_path, flow_program):
    apk = tmp_path / 'fixture.apk'
    xml = manifest('<activity android:name=".Main" android:exported="true"/>')
    with ZipFile(apk, 'w') as z:
        z.writestr('AndroidManifest.xml', xml)
        z.writestr('assets/.env', 'API_KEY=sample-secret-value')
    result = AnalysisApplication(Settings(), FixtureBackend(flow_program)).analyze(apk, Cancellation())
    assert any(f.analysis_level == 'L5' for f in result.findings)
    assert any(f.category == 'SECRETS' for f in result.findings)
    assert 'sample-secret-value' not in json.dumps([asdict(f) for f in result.findings])
    result.notes[result.findings[0].id] = 'Analyst review pending'
    output = tmp_path / 'project.json'
    save_project(output, result)
    reopened = open_project(output)
    assert reopened.to_dict() == result.to_dict()


def test_backend_failure_is_partial_not_clean(tmp_path):
    class Failing:
        def load(self, *_):
            raise BackendError('test backend unavailable')
    apk = tmp_path / 'fixture.apk'
    with ZipFile(apk, 'w') as z:
        z.writestr('AndroidManifest.xml', b'\x03\x00binary')
        z.writestr('assets/config.json', '{"password":"sample-password"}')
    result = AnalysisApplication(Settings(), Failing()).analyze(apk, Cancellation())
    assert not result.complete
    assert any('test backend unavailable' in s for s in result.diagnostics)
    assert result.findings


def test_compression_bomb_is_skipped(tmp_path):
    apk = tmp_path / 'bomb.apk'
    with ZipFile(apk, 'w', ZIP_DEFLATED) as z:
        z.writestr('assets/bomb.txt', 'a' * 2_000_000)
    _, _, _, diagnostics = inspect_apk(apk, Cancellation())
    assert any('compression ratio' in s for s in diagnostics)


def test_archive_is_not_extracted(tmp_path):
    apk = tmp_path / 'paths.apk'
    with ZipFile(apk, 'w') as z:
        z.writestr('assets/../../escape.txt', 'hello')
    inspect_apk(apk, Cancellation())
    assert not (tmp_path / 'escape.txt').exists()


def test_unknown_project_schema_rejected():
    with pytest.raises(ValueError):
        AnalysisResult.from_dict({'schema_version': 99})


def test_duplicate_rule_id_rejected(tmp_path):
    rules = tmp_path / 'bad.yaml'
    rules.write_text('sources: []\ntransfers: []\nsinks:\n - {id: same, arguments: [1]}\n - {id: same, arguments: [1]}')
    with pytest.raises(ValueError):
        RuleRegistry(rules)


def test_project_save_does_not_copy_entire_model(tmp_path, monkeypatch):
    result = AnalysisResult('app.apk', 'abc')
    monkeypatch.setattr(result, 'to_dict', lambda: (_ for _ in ()).throw(AssertionError('deep copy used')))
    target = tmp_path / 'streamed.json'
    save_project(target, result)
    assert open_project(target).sha256 == 'abc'


def test_failed_project_save_preserves_previous_file(tmp_path):
    target = tmp_path / 'project.json'
    old = AnalysisResult('old.apk', 'old')
    save_project(target, old)
    invalid = AnalysisResult('new.apk', 'new', notes={'invalid': object()})
    with pytest.raises(TypeError):
        save_project(target, invalid)
    assert open_project(target).sha256 == 'old'


def test_java_unpaired_surrogate_preserved_in_project(tmp_path):
    import json
    from analyzer.backends.jeb.protocol import decode_java_text
    value = json.loads('{"__aoseye_utf16_codepoints__": [65, 55296, 128512]}',
                       object_hook=decode_java_text)
    assert value == 'A\ud800\U0001f600'
    result = AnalysisResult('app.apk', 'abc', notes={'string': value})
    target = tmp_path / 'surrogate.json'
    save_project(target, result)
    assert open_project(target).notes['string'] == value


@pytest.mark.parametrize('transfer', [
    'Ltest/Thing;->read(',
    {'signatures': ['Ltest/Thing;->read()Ljava/lang/String;'], 'arguments': [-1]},
    {'signatures': ['Ltest/Thing;->read()Ljava/lang/String;'], 'arguments': [True]},
    {'signatures': ['Ltest/Thing;->read()Ljava/lang/String;'], 'arguments': [0], 'uncertain': 'false'},
])
def test_transfer_rule_requires_explicit_argument_schema(tmp_path, transfer):
    import yaml
    path = tmp_path / 'rules.yaml'
    path.write_text(yaml.safe_dump({'sources': [], 'transfers': [transfer], 'sinks': []}))
    with pytest.raises(ValueError, match='transfer rule'):
        RuleRegistry(path)


def test_duplicate_transfer_rejected(tmp_path):
    import copy
    import yaml
    path = tmp_path / 'rules.yaml'
    transfer = {'signatures': ['Ltest/Thing;->read()Ljava/lang/String;'], 'arguments': [0]}
    path.write_text(yaml.safe_dump({'sources': [], 'transfers': [transfer, copy.deepcopy(transfer)], 'sinks': []}))
    with pytest.raises(ValueError, match='Duplicate transfer'):
        RuleRegistry(path)


def test_candidate_review_roundtrip_and_legacy_default(tmp_path):
    from analyzer.core.models import Finding
    finding = Finding('test', 'test', '', 'WEBVIEW', review={'reachability': {'status': 'INCOMPLETE'}})
    result = AnalysisResult('app.apk', 'abc', findings=[finding])
    path = tmp_path / 'review.json'
    save_project(path, result)
    assert open_project(path).findings[0].review == finding.review
    legacy = result.to_dict()
    del legacy['findings'][0]['review']
    assert AnalysisResult.from_dict(legacy).findings[0].review == {}
