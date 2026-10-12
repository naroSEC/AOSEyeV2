import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import FILL, list_call
from analyzer.core.iteratorflow import ITERATOR, iterator_call


def fill(previous, old=None, ranged=False, registers=None, opcode=None):
    changed, diagnostics = previous.copy(), []
    handled, returned = list_call(I(4, opcode or ('invoke-static' + ('/range' if ranged else '')),
        [0, 1] if registers is None else registers, target=FILL), old or {}, changed, previous, 'test', diagnostics.append)
    assert handled and returned is None
    return changed, diagnostics


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('count', [0, 1, 3, 64])
@pytest.mark.parametrize('input_value', [False, True])
def test_fill_all_slots_and_path_isolation(ranged, count, input_value):
    prior = Trace('prior', (), True)
    value = Trace('new', (), True, True)
    items = tuple(prior if i % 2 else None for i in range(count))
    obj = ObjectValue(ARRAYLIST, list_items=items)
    previous = Memory(refs={0: 'list', 5: 'list'}, objects={'list': obj})
    changed, diagnostics = fill(previous, {1: value} if input_value else {}, ranged)
    assert not diagnostics and previous.object(0) is obj and previous.object(0).list_items == items
    assert changed.object(0) is changed.object(5) and len(changed.object(0).list_items) == count
    if not count:
        assert changed.object(0) is obj
    for index, actual in enumerate(changed.object(0).list_items):
        if input_value:
            assert actual.source == 'new' and actual.uncertain
            assert actual.steps[-1][2] == 'Collections.fill index ' + str(index)
        else:
            assert actual is None
    cleared, diagnostics = fill(changed)
    assert not diagnostics and cleared.object(0).list_items == (None,) * count


@pytest.mark.parametrize('case', ['contents', 'budget', 'no_args', 'extra_args', 'opcode', 'receiver', 'other', 'nested', 'self'])
def test_fill_unresolved_cases(case):
    obj = ObjectValue('Ljava/util/LinkedList;' if case == 'other' else ARRAYLIST,
        list_items=None if case == 'contents' else (Trace('input', (), True),) * (65 if case == 'budget' else 2))
    previous = Memory(refs={} if case == 'receiver' else {0: 'list'}, objects={'list': obj})
    if case in ('nested', 'self'):
        previous.refs[1] = 'list' if case == 'self' else 'nested'
        previous.objects['nested'] = ObjectValue(ARRAYLIST, list_items=())
    changed, diagnostics = fill(previous, registers=[] if case == 'no_args' else [0, 1, 2] if case == 'extra_args' else [0, 1],
                                opcode='invoke-virtual' if case == 'opcode' else None)
    assert diagnostics and previous.objects['list'] is obj
    if case not in ('receiver', 'other', 'no_args'):
        assert changed.object(0).list_items is None


@pytest.mark.parametrize('count', [0, 2])
def test_fill_existing_iterator_snapshot(count):
    obj = ObjectValue(ARRAYLIST, list_items=(None,) * count)
    previous = Memory(refs={0: 'list', 3: 'iterator'}, objects={'list': obj,
        'iterator': ObjectValue(ITERATOR, iterator_ref='list', iterator_snapshot=obj, iterator_index=0)})
    changed, diagnostics = fill(previous, {1: Trace('input', (), True)})
    after = changed.copy()
    iterator_call(I(6, 'invoke-interface', [3], target=ITERATOR + '->hasNext()Z'),
                  after, changed, 'test', diagnostics.append)
    assert bool(diagnostics) == bool(count)
    assert after.object(3).iterator_index == (None if count else 0)


def test_empty_fill_with_nested_value_does_not_insert():
    obj = ObjectValue(ARRAYLIST, list_items=())
    previous = Memory(refs={0: 'list', 1: 'list'}, objects={'list': obj})
    changed, diagnostics = fill(previous)
    assert not diagnostics and changed.object(0) is obj
