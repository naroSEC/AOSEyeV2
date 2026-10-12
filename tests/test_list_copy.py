import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import COPY, list_call
from analyzer.core.iteratorflow import ITERATOR, iterator_call


def copy(previous, ranged=False, registers=None, opcode=None):
    changed, diagnostics = previous.copy(), []
    handled, returned = list_call(I(4, opcode or ('invoke-static' + ('/range' if ranged else '')),
        [0, 1] if registers is None else registers, target=COPY), {}, changed, previous, 'test', diagnostics.append)
    assert handled and returned is None
    return changed, diagnostics


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('size', [0, 1, 2, 4, 64])
def test_copy_prefix_tail_alias_and_independence(ranged, size):
    old, new = Trace('old', (), True), Trace('new', (), True, True)
    source = ObjectValue(ARRAYLIST, list_items=tuple(new if i % 2 else None for i in range(size)))
    dest = ObjectValue(ARRAYLIST, list_items=(old,) * 64)
    previous = Memory(refs={0: 'dest', 1: 'source', 5: 'dest'}, objects={'dest': dest, 'source': source})
    changed, diagnostics = copy(previous, ranged)
    assert not diagnostics and previous.object(0) is dest and previous.object(1) is source
    assert changed.object(0) is changed.object(5) and changed.object(1) is source
    assert len(changed.object(0).list_items) == 64
    for index, actual in enumerate(changed.object(0).list_items):
        if index >= size:
            assert actual is old
        elif index % 2 == 0:
            assert actual is None
        else:
            assert actual.source == 'new' and actual.uncertain
            assert actual.steps[-1][2] == 'Collections.copy index ' + str(index)
    if size == 0:
        assert changed.object(0) is dest
    copied = changed.object(0)
    changed.update(1, list_items=())
    assert changed.object(0) is copied and previous.object(1) is source


@pytest.mark.parametrize('case', ['dest_contents', 'source_contents', 'short', 'budget', 'no_args', 'extra_args',
    'opcode', 'dest_missing', 'source_missing', 'dest_other', 'source_other'])
def test_copy_unresolved_invalidates_only_destination(case):
    dest = ObjectValue('Ljava/util/LinkedList;' if case == 'dest_other' else ARRAYLIST,
        list_items=None if case == 'dest_contents' else (None,) * (65 if case == 'budget' else 0 if case == 'short' else 2))
    source = ObjectValue('Ljava/util/LinkedList;' if case == 'source_other' else ARRAYLIST,
        list_items=None if case == 'source_contents' else (Trace('input', (), True),))
    previous = Memory(refs={0: 'dest', 1: 'source'}, objects={'dest': dest, 'source': source})
    if case.endswith('_missing'):
        previous.refs.pop(0 if case == 'dest_missing' else 1)
    changed, diagnostics = copy(previous, registers=[] if case == 'no_args' else [0, 1, 2] if case == 'extra_args' else None,
                                opcode='invoke-virtual' if case == 'opcode' else None)
    assert diagnostics and previous.objects['dest'] is dest and changed.objects['source'] is source
    if case not in ('dest_other', 'dest_missing', 'no_args'):
        assert changed.object(0).list_items is None


@pytest.mark.parametrize('empty', [False, True])
def test_exact_self_copy_noop(empty):
    obj = ObjectValue(ARRAYLIST, list_items=() if empty else (Trace('input', (), True), None))
    previous = Memory(refs={0: 'list', 1: 'list'}, objects={'list': obj})
    changed, diagnostics = copy(previous)
    assert not diagnostics and changed.object(0) is obj


@pytest.mark.parametrize('empty', [False, True])
def test_copy_iterator_snapshot(empty):
    dest = ObjectValue(ARRAYLIST, list_items=(None,))
    source = ObjectValue(ARRAYLIST, list_items=() if empty else (Trace('input', (), True),))
    previous = Memory(refs={0: 'dest', 1: 'source', 3: 'iterator'}, objects={'dest': dest, 'source': source,
        'iterator': ObjectValue(ITERATOR, iterator_ref='dest', iterator_snapshot=dest, iterator_index=0)})
    changed, diagnostics = copy(previous)
    after = changed.copy()
    iterator_call(I(6, 'invoke-interface', [3], target=ITERATOR + '->hasNext()Z'),
                  after, changed, 'test', diagnostics.append)
    assert bool(diagnostics) != empty
    assert after.object(3).iterator_index == (0 if empty else None)
