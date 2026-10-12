import pytest
from analyzer.core.arrayflow import clone_call
from analyzer.core.objectflow import Memory, ObjectValue
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import Trace, FlowEngine
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from conftest import method, SINK
from test_arrayflow import ENTRY


@pytest.mark.parametrize('case', ['normal', 'overwrite_source', 'overwrite_clone', 'alias_source', 'unknown', 'budget'])
def test_clone_pipeline(case, monkeypatch):
    if case == 'budget':
        monkeypatch.setattr('analyzer.core.arrayflow.MAX_ARRAY_OBJECTS', 1)
    code = [I(0, 'filled-new-array', [1], literal='[Ljava/lang/String;'),
            I(2, 'move-result-object', [4], defs=[4]),
            I(4, 'const/4', [5], defs=[5], literal=0),
            I(6, 'const-string', [6], defs=[6], literal='safe'),
            I(8, 'move-object', [7, 4], defs=[7]),
            I(10, 'invoke-virtual', [12 if case == 'unknown' else 4], target='[Ljava/lang/String;->clone()Ljava/lang/Object;'),
            I(12, 'move-result-object', [8], defs=[8])]
    if case.startswith('overwrite'):
        code.append(I(14, 'aput-object', [6, 4 if case == 'overwrite_source' else 8, 5]))
    code.extend([I(16, 'aget-object', [11, 7 if case == 'alias_source' else 8, 5], defs=[11]),
                 I(18, 'invoke-virtual', [9, 11], target=SINK), I(20, 'return-object', [11])])
    flows, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 3])}), {ENTRY}, Cancellation())
    assert bool(flows) == (case in ('normal', 'overwrite_source', 'alias_source'))
    if flows:
        assert flows[0].verification == 'LIKELY'
    if case in ('unknown', 'budget'):
        assert diagnostics


def test_clone_identity_and_uncertainty():
    previous = Memory(refs={0: ('allocation', 1)}, objects={('allocation', 1):
        ObjectValue('[Ljava/lang/Object;', array_length=2, array_elements={None: Trace('possible', (), True, True)})}, sequence=1)
    memory = previous.copy()
    assert clone_call(I(0, 'invoke-virtual/range', [0], target='[Ljava/lang/Object;->clone()Ljava/lang/Object;'),
                      memory, previous, 'test', pytest.fail)
    assert memory.result_ref != previous.refs[0]
    assert memory.objects[memory.result_ref].array_elements[None].uncertain
    assert len(previous.objects) == 1 and len(memory.objects) == 2


def test_non_array_clone_not_intercepted():
    assert not clone_call(I(0, 'invoke-virtual', [0], target='Ltest/Custom;->clone()Ljava/lang/Object;'),
                          Memory(), Memory(), 'test', pytest.fail)
