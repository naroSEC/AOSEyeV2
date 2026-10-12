import pytest
from analyzer.core.models import Instruction
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, Memory, ObjectValue
from analyzer.core.listflow import LIST, COLLECTION, list_call


def memory(items, index):
    return Memory(refs={0: ('allocation', 1), 3: ('allocation', 1)}, constants={1: index},
                  objects={('allocation', 1): ObjectValue(ARRAYLIST, list_items=items)})


def call(previous, owner, ranged, member, old=None):
    opcode = 'invoke-virtual' if owner == ARRAYLIST else 'invoke-interface'
    registers = [3, 1, 2] if member.startswith('add(') else [3, 1]
    ins = Instruction(10, opcode + ('/range' if ranged else ''), registers, target=owner + '->' + member)
    changed, diagnostics = previous.copy(), []
    handled, result = list_call(ins, old or {}, changed, previous, 'test', diagnostics.append)
    assert handled
    return changed, result, diagnostics


@pytest.mark.parametrize('owner', [ARRAYLIST, LIST])
@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('index', [0, 1, 2])
def test_insert_shifts_and_preserves_path(owner, ranged, index):
    trace = Trace('source', (), True, True)
    previous = memory((trace, None), index)
    changed, result, diagnostics = call(previous, owner, ranged, 'add(ILjava/lang/Object;)V', {2: trace})
    assert not diagnostics and result is None and changed.result_constant is None
    items = changed.object(0).list_items
    assert len(items) == 3 and items[index].source == 'source' and items[index].uncertain
    original_position = 1 if index == 0 else 0
    assert items[original_position].source == 'source'
    if index == 0:
        assert items[1].steps[-1][2] == 'ArrayList insert shift 0 -> 1'
    assert previous.object(0).list_items == (trace, None)
    assert changed.object(3) == changed.object(0)


@pytest.mark.parametrize('owner', [ARRAYLIST, LIST])
@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('index', [0, 1, 2])
def test_remove_return_shift_and_safe_slots(owner, ranged, index):
    trace = Trace('source', (), True, True)
    previous = memory((None, trace, None), index)
    changed, result, diagnostics = call(previous, owner, ranged, 'remove(I)Ljava/lang/Object;')
    assert not diagnostics
    items = changed.object(0).list_items
    assert len(items) == 2
    if index == 1:
        assert result.source == 'source' and result.uncertain
        assert result.steps[-1][2] == 'ArrayList remove index 1'
        assert items == (None, None)
    else:
        assert result is None
        shifted = items[0 if index == 0 else 1]
        assert shifted.source == 'source' and shifted.uncertain
        if index == 0:
            assert shifted.steps[-1][2] == 'ArrayList remove shift 1 -> 0'
    assert previous.object(0).list_items == (None, trace, None)


@pytest.mark.parametrize('member', ['add(ILjava/lang/Object;)V', 'remove(I)Ljava/lang/Object;'])
@pytest.mark.parametrize('index', [None, -1, 3, True])
def test_unresolved_mutation_invalidates(member, index):
    previous = memory((Trace('source', (), True),), index)
    changed, result, diagnostics = call(previous, LIST, False, member)
    assert diagnostics and result is None and changed.object(0).list_items is None


def test_empty_insertion_removal_and_budget(monkeypatch):
    previous = memory((), 0)
    changed, result, diagnostics = call(previous, LIST, False, 'add(ILjava/lang/Object;)V')
    assert not diagnostics and changed.object(0).list_items == (None,)
    changed, result, diagnostics = call(changed, LIST, False, 'remove(I)Ljava/lang/Object;')
    assert not diagnostics and changed.object(0).list_items == () and result is None
    changed, result, diagnostics = call(changed, LIST, False, 'remove(I)Ljava/lang/Object;')
    assert diagnostics and changed.object(0).list_items is None
    monkeypatch.setattr('analyzer.core.listflow.MAX_LIST_ITEMS', 0)
    changed, result, diagnostics = call(previous, ARRAYLIST, False, 'add(ILjava/lang/Object;)V')
    assert diagnostics and changed.object(0).list_items is None


@pytest.mark.parametrize('member', ['add(ILjava/lang/Object;)V', 'remove(I)Ljava/lang/Object;'])
def test_collection_does_not_have_indexed_methods(member):
    changed, result, diagnostics = call(memory((None,), 0), COLLECTION, False, member)
    assert diagnostics and result is None and changed.object(0).list_items is None
