import pytest
from analyzer.core.arrayflow import COPY_OF_RANGE, copy_of_call
from analyzer.core.objectflow import Memory, ObjectValue
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import Trace, FlowEngine
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from conftest import method, SINK
from test_arrayflow import ENTRY


@pytest.mark.parametrize('start,end,index,found', [
    (1, 2, 0, True), (0, 1, 0, False), (1, 4, 0, True), (1, 4, 2, False),
    (2, 4, 0, False), (2, 2, 0, False), (3, 4, 0, False),
    (-1, 1, 0, False), (1, 0, 0, False), (None, 2, 0, False),
    (1, None, 0, False), (0, 65, 0, False)])
def test_range_pipeline(start, end, index, found):
    code = [I(0, 'const-string', [3], defs=[3], literal='safe'),
            I(2, 'filled-new-array', [3, 1], literal='[Ljava/lang/String;'),
            I(4, 'move-result-object', [4], defs=[4]), I(6, 'const/4', [5], defs=[5], literal=start),
            I(8, 'const/4', [6], defs=[6], literal=end),
            I(10, 'invoke-static/range', [4, 5, 6], target=COPY_OF_RANGE),
            I(12, 'move-result-object', [7], defs=[7]), I(14, 'const/4', [8], defs=[8], literal=index),
            I(16, 'aget-object', [10, 7, 8], defs=[10]), I(18, 'invoke-virtual', [9, 10], target=SINK),
            I(20, 'return-object', [10])]
    flows, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 11])}), {ENTRY}, Cancellation())
    assert bool(flows) == found
    if found:
        assert flows[0].verification == 'LIKELY'
        assert any(step['label'] == 'Arrays.copyOfRange index 1 -> 0' for step in flows[0].data_flow)
    if start is None or end is None or start < 0 or start > 2 or end < start or end - start > 64:
        assert diagnostics


def test_range_wildcard_padding_and_original():
    source = ObjectValue('[Ljava/lang/Object;', array_length=2,
                         array_elements={None: Trace('input', (), True, True)})
    previous = Memory(refs={0: ('allocation', 1)}, constants={1: 1, 2: 4},
                      objects={('allocation', 1): source}, sequence=1)
    memory = previous.copy()
    copy_of_call(I(0, 'invoke-static', [0, 1, 2], target=COPY_OF_RANGE), memory, previous, 'test', pytest.fail)
    copied = memory.objects[memory.result_ref]
    assert copied.array_length == 3 and copied.array_elements[0].uncertain
    assert set(copied.array_elements) == {0}
    assert memory.object(0) == previous.object(0) == source and memory.result_ref != previous.refs[0]
