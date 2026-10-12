import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import LIST, COLLECTION, ADD_ALL, ADD_ALL_INDEXED, list_call


def state():
    return Memory(refs={0: ('allocation', 1), 1: ('allocation', 2), 3: ('allocation', 1)},
        constants={2: 1}, sequence=2,
        objects={('allocation', 1): ObjectValue(ARRAYLIST, list_items=(None, Trace('tail', (), True))),
                 ('allocation', 2): ObjectValue(ARRAYLIST, list_items=(Trace('input', (), True, True), None))})


def call(previous, owner=LIST, indexed=False, ranged=False):
    changed, diagnostics = previous.copy(), []
    op = 'invoke-virtual' if owner == ARRAYLIST else 'invoke-interface'
    handled, result = list_call(I(10, op + ('/range' if ranged else ''), [0, 2, 1] if indexed else [0, 1],
                                   target=owner + '->' + (ADD_ALL_INDEXED if indexed else ADD_ALL)),
                               {}, changed, previous, 'test', diagnostics.append)
    assert handled and result is None
    return changed, diagnostics


@pytest.mark.parametrize('owner,indexed', [(ARRAYLIST, False), (ARRAYLIST, True), (LIST, False), (LIST, True), (COLLECTION, False)])
@pytest.mark.parametrize('ranged', [False, True])
def test_order_alias_uncertainty_and_source_independence(owner, indexed, ranged):
    previous = state()
    changed, diagnostics = call(previous, owner, indexed, ranged)
    assert not diagnostics and changed.result_constant == 1
    index = 1 if indexed else 2
    items = changed.object(0).list_items
    assert len(items) == 4 and items[index].source == 'input' and items[index].uncertain
    assert items[index + 1] is None and items[0] is None
    assert items[3 if indexed else 1].source == 'tail'
    if indexed:
        assert items[3].steps[-1][2] == 'ArrayList addAll shift 1 -> 3'
    assert changed.object(3) == changed.object(0)
    assert changed.object(1) == previous.object(1)
    changed.update(1, list_items=())
    assert changed.object(0).list_items[index].source == 'input'
    assert len(previous.object(0).list_items) == 2


@pytest.mark.parametrize('index', [0, 2])
def test_index_boundaries(index):
    previous = state()
    previous.constants[2] = index
    changed, diagnostics = call(previous, indexed=True)
    assert not diagnostics and changed.object(0).list_items[index].source == 'input'


@pytest.mark.parametrize('indexed', [False, True])
def test_empty_source_is_unchanged_and_false(indexed):
    previous = state()
    previous.update(1, list_items=())
    changed, diagnostics = call(previous, indexed=indexed)
    assert not diagnostics and changed.result_constant == 0
    assert changed.object(0) == previous.object(0)


@pytest.mark.parametrize('case', ['unknown_source', 'other_source', 'source_contents', 'destination_contents',
    'self', 'empty_self', 'negative', 'unknown_index', 'out_of_range', 'budget', 'collection_indexed'])
def test_unresolved_addall_invalidates_only_destination(case, monkeypatch):
    previous = state()
    if case == 'unknown_source':
        previous.refs.pop(1)
    elif case == 'other_source':
        previous.update(1, type='Ljava/util/LinkedList;')
    elif case == 'source_contents':
        previous.update(1, list_items=None)
    elif case == 'destination_contents':
        previous.update(0, list_items=None)
    elif case in ('self', 'empty_self'):
        previous.refs[1] = previous.refs[0]
        if case == 'empty_self':
            previous.update(0, list_items=())
    elif case in ('negative', 'unknown_index', 'out_of_range'):
        previous.constants[2] = {'negative': -1, 'unknown_index': None, 'out_of_range': 3}[case]
    elif case == 'budget':
        monkeypatch.setattr('analyzer.core.listflow.MAX_LIST_ITEMS', 3)
    changed, diagnostics = call(previous, COLLECTION if case == 'collection_indexed' else LIST, indexed=True)
    assert diagnostics and changed.result_constant is None and changed.object(0).list_items is None
    if case not in ('self', 'empty_self'):
        assert changed.object(1) == previous.object(1)
