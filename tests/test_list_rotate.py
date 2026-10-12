import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import ROTATE, list_call
from analyzer.core.iteratorflow import ITERATOR, iterator_call


def rotate(previous, ranged=False, registers=None, opcode=None):
    changed, diagnostics = previous.copy(), []
    handled, returned = list_call(I(4, opcode or ('invoke-static' + ('/range' if ranged else '')),
        [0, 1] if registers is None else registers, target=ROTATE), {}, changed, previous, 'test', diagnostics.append)
    assert handled and returned is None
    return changed, diagnostics


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('count,distance', [(0, 1), (1, -1), (3, 0), (3, 1), (3, -1), (3, 4),
    (3, -4), (3, 3), (3, -6), (3, -2147483648), (3, 2147483647), (64, 65)])
def test_rotate_slots_and_restore(count, distance, ranged):
    items = tuple(Trace('input-' + str(i), (), True, i % 2 == 0) if i % 3 != 1 else None for i in range(count))
    obj = ObjectValue(ARRAYLIST, list_items=items)
    previous = Memory(refs={0: 'list', 5: 'list'}, constants={1: distance}, objects={'list': obj})
    changed, diagnostics = rotate(previous, ranged)
    assert not diagnostics and previous.object(0) is obj and previous.object(0).list_items == items
    assert changed.object(0) is changed.object(5) and len(changed.object(0).list_items) == count
    shift = distance % count if count else 0
    for source, original in enumerate(items):
        destination = (source + shift) % count
        actual = changed.object(0).list_items[destination]
        if original is None:
            assert actual is None
        elif shift == 0:
            assert actual is original
        else:
            assert actual.source == original.source and actual.uncertain == original.uncertain
            assert actual.steps[-1][2] == 'Collections.rotate index %d -> %d' % (source, destination)
    if shift == 0:
        assert changed.object(0) is obj
    changed.constants[1] = -shift  # Avoid negating Java MIN_VALUE outside int range.
    restored, diagnostics = rotate(changed, ranged)
    assert not diagnostics
    for actual, original in zip(restored.object(0).list_items, items):
        assert (actual.source, actual.uncertain) == (original.source, original.uncertain) if original else actual is None


@pytest.mark.parametrize('case', ['contents', 'budget', 'no_args', 'extra_args', 'opcode', 'receiver', 'other',
    'unknown', 'bool', 'float', 'too_small', 'too_large'])
def test_rotate_unresolved_cases(case):
    obj = ObjectValue('Ljava/util/LinkedList;' if case == 'other' else ARRAYLIST,
        list_items=None if case == 'contents' else (Trace('input', (), True),) * (65 if case == 'budget' else 2))
    distance = {'unknown': None, 'bool': True, 'float': 1.0, 'too_small': -2147483649, 'too_large': 2147483648}.get(case, 1)
    previous = Memory(refs={} if case == 'receiver' else {0: 'list'}, constants={1: distance}, objects={'list': obj})
    changed, diagnostics = rotate(previous, registers=[] if case == 'no_args' else [0, 1, 2] if case == 'extra_args' else [0, 1],
                                  opcode='invoke-virtual' if case == 'opcode' else None)
    assert diagnostics and previous.objects['list'] is obj
    if case not in ('receiver', 'other', 'no_args'):
        assert changed.object(0).list_items is None


@pytest.mark.parametrize('distance', [0, 1, 2])
def test_rotate_existing_iterator_snapshot(distance):
    obj = ObjectValue(ARRAYLIST, list_items=(Trace('input', (), True), None))
    previous = Memory(refs={0: 'list', 3: 'iterator'}, constants={1: distance}, objects={'list': obj,
        'iterator': ObjectValue(ITERATOR, iterator_ref='list', iterator_snapshot=obj, iterator_index=0)})
    changed, diagnostics = rotate(previous)
    after = changed.copy()
    _, result = iterator_call(I(6, 'invoke-interface', [3], target=ITERATOR + '->next()Ljava/lang/Object;'),
                              after, changed, 'test', diagnostics.append)
    assert bool(diagnostics) == (distance == 1)
    assert bool(result) == (distance != 1)
