import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from analyzer.app.settings import Settings
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.backends.jeb.backend import JebBackend, file_hash
from analyzer.backends.base import BackendError
from analyzer.core.models import Program, Method, Instruction


@pytest.fixture
def candidate(tmp_path):
    path = tmp_path / 'input.dex'
    path.write_bytes(b'fixture')
    backend = JebBackend(Settings(cache_enabled=False))
    backend.input_path, backend.input_sha256 = path, file_hash(path)
    caller, target = 'Lcaller;->run()V', 'Ltarget;->run()V'
    backend.program = Program(methods={caller: Method(caller, unit='u', instructions=[
        Instruction(0, 'invoke-static', target=target)])},
        method_index=[dict(signature=target, unit='u', declared=True, has_code=True)])
    yield backend, caller, target
    backend.close()


def response(target):
    value = dict(signature=target, unit='u', instructions=[])
    return dict(status='CANDIDATE', method=value, encoded_bytes=len(json.dumps(value) + '\n'), byte_limit=262144)


def test_preview_no_mutation(candidate, monkeypatch):
    backend, caller, target = candidate
    before = deepcopy(backend.program)
    def request(operation, token, **kwargs):
        assert operation == 'method_candidate'
        assert kwargs['unit'] == 'u' and kwargs['method'] == target
        assert kwargs['input_sha256'] == backend.input_sha256
        return response(target)
    monkeypatch.setattr(backend.session, 'request', request)
    value = backend.preview_call_target(caller, 0, Cancellation())
    assert value['status'] == 'CANDIDATE'
    assert backend.program == before
    backend.input_sha256 = ''
    with pytest.raises(BackendError, match='fingerprint'):
        backend.preview_call_target(caller, 0, Cancellation())


@pytest.mark.parametrize('case', ['virtual', 'duplicate_offset', 'unknown_unit', 'ambiguous', 'unindexed', 'changed_input', 'budget'])
def test_preflight_rejection(candidate, monkeypatch, case):
    backend, caller, target = candidate
    method = backend.program.methods[caller]
    if case == 'virtual':
        method.instructions[0].opcode = 'invoke-virtual'
    elif case == 'duplicate_offset':
        method.instructions.append(deepcopy(method.instructions[0]))
    elif case == 'unknown_unit':
        backend.program.method_index[0]['unit'] = ''
    elif case == 'ambiguous':
        backend.program.method_index.append(dict(backend.program.method_index[0], unit='v'))
    elif case == 'unindexed':
        backend.program.method_index.clear()
    elif case == 'changed_input':
        backend.input_path.write_bytes(b'changed')
    monkeypatch.setattr(backend.session, 'request', lambda *a, **kw: pytest.fail('Must not contact JEB'))
    with pytest.raises((ValueError, BackendError)):
        backend.preview_call_target(caller, 0, Cancellation(), max_bytes=0 if case == 'budget' else 262144)


@pytest.mark.parametrize('case', ['budget', 'wrong_unit', 'oversize', 'late_cancel'])
def test_response_guards(candidate, monkeypatch, case):
    backend, caller, target = candidate
    before = deepcopy(backend.program)
    token = Cancellation()
    def request(*a, **kw):
        result = response(target)
        if case == 'budget':
            return dict(status='BUDGET_EXCEEDED', byte_limit=262144)
        if case == 'wrong_unit':
            result['method']['unit'] = 'wrong'
        if case == 'oversize':
            result['method']['source'] = 'x' * 262144
        if case == 'late_cancel':
            token.cancel()
        return result
    monkeypatch.setattr(backend.session, 'request', request)
    if case == 'budget':
        assert backend.preview_call_target(caller, 0, token)['status'] == 'BUDGET_EXCEEDED'
    else:
        with pytest.raises((BackendError, Cancelled)):
            backend.preview_call_target(caller, 0, token)
    assert backend.program == before


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_live_candidate_and_tiny_budget():
    path = Path(__file__).resolve().parents[1] / 'build/fixtures/flow-fixture.apk'
    with JebBackend(Settings(cache_enabled=False, jvm_heap_mib=1024)) as backend:
        program = backend.load(path, Cancellation())
        candidates = [(m.signature, ins.offset, ins.target) for m in program.methods.values()
            for ins in m.instructions if ins.opcode in ('invoke-static', 'invoke-direct')
            and ins.target in program.methods and ins.target != m.signature]
        assert candidates
        caller, offset, target = candidates[0]
        removed = program.methods.pop(target)
        before = deepcopy(program)
        limited = backend.preview_call_target(caller, offset, Cancellation(), max_bytes=1)
        assert limited['status'] == 'BUDGET_EXCEEDED'
        value = backend.preview_call_target(caller, offset, Cancellation())
        assert value['status'] == 'CANDIDATE'
        assert value['method']['signature'] == removed.signature
        assert value['method']['unit'] == removed.unit
        assert program == before and target not in program.methods


@pytest.mark.parametrize('case', ['duplicate', 'unit_mismatch', 'no_code', 'bad_limit'])
def test_bridge_rejects_global_ambiguity_and_invalid_candidate(case):
    import ast
    from types import SimpleNamespace as NS
    script = Path(__file__).resolve().parents[1] / 'src/analyzer/backends/jeb/scripts/AOSEyeBridge.py'
    tree = ast.parse(script.read_text(encoding='utf-8'))
    function = next(n for c in tree.body if isinstance(c, ast.ClassDef)
                    for n in c.body if isinstance(n, ast.FunctionDef) and n.name == 'execute')
    scope = {'IDexUnit': object}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(script), 'exec'), scope)
    method = NS(getData=lambda: NS(getCodeItem=lambda: None if case == 'no_code' else object()))
    unit = NS(isProcessed=lambda: True, getMethod=lambda _: method)
    units = [unit, unit] if case == 'duplicate' else [unit]
    ctx = NS(open=lambda *a: None, project=NS(findUnits=lambda _: units), capabilities={})
    bridge = NS(unit_id=lambda n, d: str(n), method=lambda *a: pytest.fail('Must reject before normalization'))
    request = dict(operation='method_candidate', input='fixture', input_sha256='hash',
                   method='Ltarget;->run()V', unit='wrong' if case == 'unit_mismatch' else '0',
                   max_candidate_bytes=0 if case == 'bad_limit' else 262144)
    with pytest.raises(ValueError):
        scope['execute'](bridge, ctx, request)
