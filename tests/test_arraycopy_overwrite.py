import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ObjectValue, Memory
from analyzer.core.arrayflow import ARRAYCOPY, copy_call


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('count', [0, 1, 3])
@pytest.mark.parametrize('source_input', [False, True])
def test_copy_removes_destination_wildcard_only_in_written_range(ranged, count, source_input):
    stale, incoming = Trace('stale', (), True), Trace('incoming', (), True, True)
    source = ObjectValue('[Ljava/lang/Object;', array_length=3,
                         array_elements={0: incoming} if source_input else {})
    dest = ObjectValue('[Ljava/lang/Object;', array_length=3, array_elements={None: stale})
    previous = Memory(refs={0: 'source', 2: 'dest', 5: 'dest'}, constants={1: 0, 3: 0, 4: count},
                      objects={'source': source, 'dest': dest})
    changed, diagnostics = previous.copy(), []
    assert copy_call(I(4, 'invoke-static' + ('/range' if ranged else ''), [0, 1, 2, 3, 4], target=ARRAYCOPY),
                     changed, previous, 'test', diagnostics.append)
    assert not diagnostics and previous.object(2) is dest and changed.object(0) is source
    assert changed.object(2) is changed.object(5)
    if count == 0:
        assert changed.object(2) is dest
        return
    slots = changed.object(2).array_elements
    assert None not in slots
    for index in range(3):
        if index >= count:
            assert slots[index].source == 'stale' and slots[index].uncertain
        elif index == 0 and source_input:
            assert slots[index].source == 'incoming' and slots[index].uncertain
        else:
            assert slots[index] is None


def test_overlapping_copy_reads_original_wildcard():
    obj = ObjectValue('[Ljava/lang/Object;', array_length=3,
                      array_elements={None: Trace('input', (), True)})
    previous = Memory(refs={0: 'array', 2: 'array'}, constants={1: 0, 3: 1, 4: 2}, objects={'array': obj})
    changed, diagnostics = previous.copy(), []
    assert copy_call(I(4, 'invoke-static', [0, 1, 2, 3, 4], target=ARRAYCOPY),
                     changed, previous, 'test', diagnostics.append)
    assert not diagnostics and previous.object(0) is obj
    assert None not in changed.object(0).array_elements
    assert all(v.source == 'input' and v.uncertain for v in changed.object(0).array_elements.values())


@pytest.mark.parametrize('length', [65, -1, True])
def test_copy_does_not_expand_invalid_destination_length(length):
    previous = Memory(refs={0: 'source', 2: 'dest'}, constants={1: 0, 3: 0, 4: 1}, objects={
        'source': ObjectValue('[Ljava/lang/Object;', array_length=1),
        'dest': ObjectValue('[Ljava/lang/Object;', array_length=length, array_elements={None: Trace('input', (), True)})})
    changed, diagnostics = previous.copy(), []
    assert copy_call(I(4, 'invoke-static', [0, 1, 2, 3, 4], target=ARRAYCOPY), changed, previous, 'test', diagnostics.append)
    assert diagnostics and changed.object(2).array_length is None
