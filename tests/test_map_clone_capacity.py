import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import HASHMAP, ObjectValue, Memory
from analyzer.core.mapflow import MAP, CLONE, CAPACITY_INIT, map_call


def invoke(previous, member, ranged=False, owner=HASHMAP):
    changed, diagnostics = previous.copy(), []
    opcode = 'invoke-direct' if member == CAPACITY_INIT else 'invoke-virtual'
    handled, value = map_call(I(10, opcode + ('/range' if ranged else ''),
        [0, 1] if member == CAPACITY_INIT else [0], target=owner + '->' + member),
        {}, changed, previous, 'test', diagnostics.append)
    assert handled and value is None
    return changed, diagnostics


@pytest.mark.parametrize('capacity', [0, 1, 64, 1000, 2147483647, -1, None, True, 2147483648])
@pytest.mark.parametrize('ranged', [False, True])
def test_capacity_initializes_empty_not_reserved_slots(capacity, ranged):
    previous = Memory(refs={0: ('allocation', 1)}, constants={1: capacity},
        objects={('allocation', 1): ObjectValue(HASHMAP)}, sequence=1)
    changed, diagnostics = invoke(previous, CAPACITY_INIT, ranged)
    valid = type(capacity) is int and 0 <= capacity <= 2147483647
    assert bool(diagnostics) != valid and changed.object(0).map_items == ({} if valid else None)
    assert changed.sequence == 1 and changed.result_ref is None and previous.object(0).map_items is None


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('empty', [False, True])
def test_clone_independent_identity_and_maps(ranged, empty):
    items = {} if empty else {'input': Trace('input', (), True, True), 'safe': None}
    previous = Memory(refs={0: ('allocation', 1)}, objects={('allocation', 1): ObjectValue(HASHMAP, map_items=items)}, sequence=1)
    changed, diagnostics = invoke(previous, CLONE, ranged)
    assert not diagnostics and changed.result_ref != previous.refs[0]
    clone = changed.objects[changed.result_ref]
    assert clone.map_items is not previous.object(0).map_items
    changed.update(0, map_items={})
    if not empty:
        assert clone.map_items['input'].uncertain and clone.map_items['safe'] is None
        assert clone.map_items['input'].steps[-1][2] == 'HashMap clone'
    assert previous.object(0).map_items == items


@pytest.mark.parametrize('case', ['unknown', 'object_budget', 'item_budget', 'interface'])
def test_clone_failure(case, monkeypatch):
    previous = Memory(refs={0: ('allocation', 1)}, sequence=1,
        objects={('allocation', 1): ObjectValue(HASHMAP, map_items=None if case == 'unknown' else {'key': None})})
    if case == 'object_budget':
        monkeypatch.setattr('analyzer.core.mapflow.MAX_MAP_OBJECTS', 1)
    if case == 'item_budget':
        monkeypatch.setattr('analyzer.core.mapflow.MAX_MAP_ITEMS', 0)
    changed, diagnostics = invoke(previous, CLONE, owner=MAP if case == 'interface' else HASHMAP)
    assert diagnostics and changed.result_ref is None and changed.sequence == 1
    if case != 'interface':
        assert changed.object(0) == previous.object(0)
