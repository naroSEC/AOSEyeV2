import pytest
from analyzer.core.arrayflow import COPY_OF, copy_of_call
from analyzer.core.objectflow import Memory, ObjectValue
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import Trace, FlowEngine
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from conftest import method, SINK
from test_arrayflow import ENTRY


@pytest.mark.parametrize('length,index,found', [(1, 0, True), (3, 0, True), (3, 2, False),
    (0, 0, False), (-1, 0, False), (65, 0, False), (None, 0, False)])
def test_copyof_pipeline(length, index, found):
    code = [I(0, 'filled-new-array', [1], literal='[Ljava/lang/String;'),
            I(2, 'move-result-object', [4], defs=[4]), I(4, 'const/4', [5], defs=[5], literal=length),
            I(6, 'invoke-static', [4, 5], target=COPY_OF), I(8, 'move-result-object', [6], defs=[6]),
            I(10, 'const/4', [7], defs=[7], literal=index), I(12, 'aget-object', [8, 6, 7], defs=[8]),
            I(14, 'invoke-virtual', [9, 8], target=SINK), I(16, 'return-object', [8])]
    flows, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 3])}), {ENTRY}, Cancellation())
    assert bool(flows) == found
    if found:
        assert flows[0].verification == 'LIKELY'
    if length in (-1, 65, None):
        assert diagnostics


def test_wildcard_does_not_taint_padding_and_source_is_unchanged():
    source = ObjectValue('[Ljava/lang/String;', array_length=1,
                         array_elements={None: Trace('input', (), True, True)})
    previous = Memory(refs={0: ('allocation', 1)}, constants={1: 3},
                      objects={('allocation', 1): source}, sequence=1)
    memory = previous.copy()
    assert copy_of_call(I(0, 'invoke-static/range', [0, 1], target=COPY_OF), memory, previous, 'test', pytest.fail)
    copied = memory.objects[memory.result_ref]
    assert memory.result_ref != previous.refs[0] and copied.type == source.type
    assert copied.array_elements[0].uncertain
    assert None not in copied.array_elements and 1 not in copied.array_elements and 2 not in copied.array_elements
    assert previous.object(0) == memory.object(0) == source


def test_truncation_drops_source_tail():
    previous = Memory(refs={0: ('allocation', 1)}, constants={1: 1}, objects={('allocation', 1):
        ObjectValue('[Ljava/lang/String;', array_length=2, array_elements={1: Trace('input', (), True)})}, sequence=1)
    memory = previous.copy()
    copy_of_call(I(0, 'invoke-static', [0, 1], target=COPY_OF), memory, previous, 'test', pytest.fail)
    assert not any(memory.objects[memory.result_ref].array_elements.values())


def test_copyof_budget(monkeypatch):
    monkeypatch.setattr('analyzer.core.arrayflow.MAX_ARRAY_OBJECTS', 1)
    previous = Memory(refs={0: ('allocation', 1)}, constants={1: 1}, objects={('allocation', 1):
        ObjectValue('[Ljava/lang/Object;', array_length=1)}, sequence=1)
    memory = previous.copy()
    diagnostics = []
    copy_of_call(I(0, 'invoke-static', [0, 1], target=COPY_OF), memory, previous, 'test', diagnostics.append)
    assert diagnostics and memory.result_ref is None and memory.objects == previous.objects
