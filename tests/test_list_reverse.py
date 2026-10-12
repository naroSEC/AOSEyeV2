import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import REVERSE, list_call
from analyzer.core.iteratorflow import ITERATOR, iterator_call


def reverse(previous, ranged=False, registers=None, opcode=None):
    changed, diagnostics = previous.copy(), []
    handled, returned = list_call(I(4, opcode or ('invoke-static' + ('/range' if ranged else '')),
        [0] if registers is None else registers, target=REVERSE), {}, changed, previous, 'test', diagnostics.append)
    assert handled and returned is None
    return changed, diagnostics


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('count', [0, 1, 2, 3, 4, 63, 64])
def test_reverse_positions_and_double_reverse(count, ranged):
    items = tuple(Trace('input-' + str(index), (), True, index % 2 == 0) if index % 3 != 1 else None
                  for index in range(count))
    obj = ObjectValue(ARRAYLIST, list_items=items)
    previous = Memory(refs={0: 'list', 5: 'list'}, objects={'list': obj})
    changed, diagnostics = reverse(previous, ranged)
    assert not diagnostics and previous.object(0) is obj
    assert previous.object(0).list_items == items
    assert changed.object(0) is changed.object(5)
    assert len(changed.object(0).list_items) == count
    for index, value in enumerate(reversed(items)):
        actual = changed.object(0).list_items[index]
        if value is None:
            assert actual is None
        elif index == count - 1 - index:
            assert actual is value
        else:
            assert actual.source == value.source and actual.uncertain == value.uncertain
            assert actual.steps[-1][2] == 'Collections.reverse index %d -> %d' % (count - 1 - index, index)
    if count < 2:
        assert changed.object(0) is obj
    restored, diagnostics = reverse(changed, ranged)
    assert not diagnostics
    for actual, original in zip(restored.object(0).list_items, items):
        if original is None:
            assert actual is None
        else:
            assert actual.source == original.source and actual.uncertain == original.uncertain


@pytest.mark.parametrize('case', ['contents', 'budget', 'no_args', 'extra_args', 'opcode', 'receiver', 'other'])
def test_reverse_unresolved_cases(case):
    obj = ObjectValue('Ljava/util/LinkedList;' if case == 'other' else ARRAYLIST,
        list_items=None if case == 'contents' else (Trace('input', (), True),) * (65 if case == 'budget' else 2))
    previous = Memory(refs={} if case == 'receiver' else {0: 'list'}, objects={'list': obj})
    changed, diagnostics = reverse(previous, registers=[] if case == 'no_args' else [0, 1] if case == 'extra_args' else [0],
                                   opcode='invoke-virtual' if case == 'opcode' else None)
    assert diagnostics and previous.objects['list'] is obj
    if case not in ('receiver', 'other', 'no_args'):
        assert changed.object(0).list_items is None


@pytest.mark.parametrize('count', [1, 2])
def test_reverse_existing_iterator_snapshot(count):
    obj = ObjectValue(ARRAYLIST, list_items=(Trace('input', (), True),) * count)
    previous = Memory(refs={0: 'list', 3: 'iterator'}, objects={'list': obj,
        'iterator': ObjectValue(ITERATOR, iterator_ref='list', iterator_snapshot=obj, iterator_index=0)})
    changed, diagnostics = reverse(previous)
    after = changed.copy()
    _, result = iterator_call(I(6, 'invoke-interface', [3], target=ITERATOR + '->next()Ljava/lang/Object;'),
                              after, changed, 'test', diagnostics.append)
    assert bool(diagnostics) == (count == 2)
    assert bool(result) == (count == 1)
