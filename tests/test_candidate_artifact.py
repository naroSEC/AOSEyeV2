from copy import deepcopy
import json

import pytest

from analyzer.app.candidate_artifact import snapshot, save_candidate, open_candidate, validate_artifact
from analyzer.app.project_manager import open_project
from test_dex_browser import browser


def artifact():
    method = dict(signature='Ltarget;->run()V', unit='u', instructions=[])
    return snapshot(dict(status='CANDIDATE', method=method, encoded_bytes=len(json.dumps(method) + '\n'),
        byte_limit=262144, input_sha256='a' * 64, caller='Lcaller;->run()V', caller_unit='u',
        opcode='invoke-static', offset=0, scope='Single direct/static target; not merged or reanalyzed'), 'fixture-version')


def test_roundtrip_separate_format(tmp_path):
    value = artifact()
    path = tmp_path / 'test.candidate.json'
    save_candidate(path, value)
    assert open_candidate(path) == value
    with pytest.raises(ValueError):
        open_project(path)
    original = path.read_bytes()
    with pytest.raises(OSError):
        save_candidate(path, value)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob('.aoseye-*'))


@pytest.mark.parametrize('case', ['hash', 'budget', 'unit', 'origin', 'schema', 'unknown_key', 'timestamp'])
def test_reject_invalid_artifact(case):
    value = artifact()
    if case == 'hash':
        value['body_sha256'] = '0' * 64
    elif case == 'budget':
        value['candidate']['byte_limit'] = 1
    elif case == 'unit':
        value['candidate']['method']['unit'] = ''
    elif case == 'origin':
        value['candidate']['input_sha256'] = 'missing'
    elif case == 'schema':
        value['schema'] = True
    elif case == 'unknown_key':
        value['extra'] = 1
    elif case == 'timestamp':
        value['queried_at_utc'] = '2026-10-04T12:00:00'
    with pytest.raises(ValueError):
        validate_artifact(value)


def test_publish_failure_preserves_files(tmp_path, monkeypatch):
    import analyzer.app.candidate_artifact as module
    def denied(*args):
        raise OSError('fixture denied')
    monkeypatch.setattr(module.os, 'link', denied)
    path = tmp_path / 'new.candidate.json'
    with pytest.raises(OSError):
        save_candidate(path, artifact())
    assert not path.exists() and not list(tmp_path.iterdir())
    with pytest.raises(ValueError):
        save_candidate(tmp_path / 'project.json', artifact())


def test_gui_export_failure_discard_and_origin_snapshot(browser, tmp_path):
    w, _ = browser
    value = artifact()
    w._candidate_record = deepcopy(value)
    w._candidate_text = 'preview'
    before = deepcopy(w._result.to_dict())
    # Changing current settings/result data must not rewrite the captured origin.
    path = tmp_path / 'gui.candidate.json'
    assert w.exportCandidate(str(path))
    assert open_candidate(path) == value
    assert not w.exportCandidate(str(path))
    assert w.candidateText == 'preview' and w._candidate_record == value
    assert w._result.to_dict() == before
    w.discardCandidate()
    assert w._candidate_record is None
    assert not w.exportCandidate(str(tmp_path / 'discarded.candidate.json'))
