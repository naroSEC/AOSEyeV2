import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import LIST, CAPACITY_INIT, COLLECTION_INIT, list_call


def state():
    return Memory(refs={0: ('allocation', 1), 1: ('allocation', 2), 3: ('allocation', 1)}, sequence=2,
        objects={('allocation', 1): ObjectValue(ARRAYLIST),
                 ('allocation', 2): ObjectValue(ARRAYLIST, list_items=(Trace('input', (), True, True), None))})


def initialize(previous, member, ranged=False, owner=ARRAYLIST, opcode='invoke-direct', registers=None):
    changed, diagnostics = previous.copy(), []
    handled, result = list_call(I(10, opcode + ('/range' if ranged else ''),
                                   [0, 1] if registers is None else registers, target=owner + '->' + member),
                               {}, changed, previous, 'test', diagnostics.append)
    assert handled and result is None and changed.result_ref is None
    return changed, diagnostics


@pytest.mark.parametrize('capacity', [0, 1, 64, 1000, 2147483647, -1, None, True, 2147483648])
@pytest.mark.parametrize('ranged', [False, True])
def test_capacity_not_size(capacity, ranged):
    previous = state()
    previous.constants[1] = capacity
    changed, diagnostics = initialize(previous, CAPACITY_INIT, ranged)
    valid = type(capacity) is int and 0 <= capacity <= 2147483647
    assert bool(diagnostics) != valid
    assert changed.object(0).list_items == (() if valid else None)
    assert changed.sequence == previous.sequence and previous.object(0).list_items is None


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('empty', [False, True])
def test_collection_copy_preserves_uncertainty_and_independence(ranged, empty):
    previous = state()
    if empty:
        previous.update(1, list_items=())
    changed, diagnostics = initialize(previous, COLLECTION_INIT, ranged)
    assert not diagnostics and changed.object(3) == changed.object(0)
    assert changed.object(1) == previous.object(1)
    if empty:
        assert changed.object(0).list_items == ()
    else:
        assert changed.object(0).list_items[0].uncertain
        assert changed.object(0).list_items[0].steps[-1][2] == 'ArrayList constructor copy index 0'
        assert changed.object(0).list_items[1] is None
        changed.update(1, list_items=())
        assert changed.object(0).list_items[0].source == 'input'
        changed.update(0, list_items=())
        assert previous.object(1).list_items[0].source == 'input'


@pytest.mark.parametrize('case', ['unknown', 'contents', 'other', 'self', 'budget', 'interface', 'virtual', 'arity'])
def test_invalid_copy_is_diagnostic(case, monkeypatch):
    previous = state()
    if case == 'unknown':
        previous.refs.pop(1)
    elif case == 'contents':
        previous.update(1, list_items=None)
    elif case == 'other':
        previous.update(1, type='Ljava/util/LinkedList;')
    elif case == 'self':
        previous.refs[1] = previous.refs[0]
        previous.update(0, list_items=())
    elif case == 'budget':
        monkeypatch.setattr('analyzer.core.listflow.MAX_LIST_ITEMS', 1)
    changed, diagnostics = initialize(previous, COLLECTION_INIT,
        owner=LIST if case == 'interface' else ARRAYLIST,
        opcode='invoke-virtual' if case == 'virtual' else 'invoke-direct', registers=[0] if case == 'arity' else None)
    assert diagnostics and changed.object(0).list_items is None
    if case != 'self':
        assert changed.object(1) == previous.object(1)
