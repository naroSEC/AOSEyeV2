import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import LIST, COLLECTION, list_call


def state(items):
    return Memory(refs={0: ('allocation', 1)}, objects={('allocation', 1): ObjectValue(ARRAYLIST, list_items=items)}, sequence=1)


def call(previous, member, owner=ARRAYLIST, ranged=False):
    changed, diagnostics = previous.copy(), []
    changed.result_ref = changed.result_constant = None
    op = 'invoke-virtual' if owner == ARRAYLIST else 'invoke-interface'
    handled, result = list_call(I(10, op + ('/range' if ranged else ''), [0], target=owner + '->' + member),
                               {}, changed, previous, 'test', diagnostics.append)
    assert handled and result is None
    return changed, diagnostics


@pytest.mark.parametrize('owner', [ARRAYLIST, LIST, COLLECTION])
@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('items', [(), (Trace('input', (), True), None), None])
def test_size_and_empty_do_not_change_contents(owner, ranged, items):
    previous = state(items)
    for member in ('size()I', 'isEmpty()Z'):
        changed, diagnostics = call(previous, member, owner, ranged)
        assert changed.object(0) == previous.object(0) and changed.result_ref is None
        if items is None:
            assert diagnostics and changed.result_constant is None
        else:
            assert not diagnostics
            assert changed.result_constant == (len(items) if member == 'size()I' else int(not items))


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('empty', [False, True])
def test_clone_new_identity_and_independent_slots(ranged, empty):
    previous = state(() if empty else (Trace('input', (), True, True), None))
    changed, diagnostics = call(previous, 'clone()Ljava/lang/Object;', ranged=ranged)
    assert not diagnostics and changed.result_ref != previous.refs[0]
    identity = changed.result_ref
    cloned = changed.objects[identity]
    assert cloned.type == ARRAYLIST and len(cloned.list_items) == (0 if empty else 2)
    changed.update(0, list_items=())
    assert changed.objects[identity] == cloned
    if not empty:
        assert cloned.list_items[0].uncertain and cloned.list_items[1] is None
        assert cloned.list_items[0].steps[-1][2] == 'ArrayList clone index 0'
    assert previous.sequence == 1


@pytest.mark.parametrize('case', ['unknown', 'object_budget', 'item_budget', 'interface'])
def test_clone_failure_no_synthetic_result(case, monkeypatch):
    previous = state(None if case == 'unknown' else (Trace('input', (), True),))
    if case == 'object_budget':
        monkeypatch.setattr('analyzer.core.listflow.MAX_LIST_OBJECTS', 1)
    if case == 'item_budget':
        monkeypatch.setattr('analyzer.core.listflow.MAX_LIST_ITEMS', 0)
    changed, diagnostics = call(previous, 'clone()Ljava/lang/Object;', LIST if case == 'interface' else ARRAYLIST)
    assert diagnostics and changed.result_ref is None and changed.sequence == previous.sequence
    if case != 'interface':
        assert changed.object(0) == previous.object(0)
