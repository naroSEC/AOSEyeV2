import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import SWAP, list_call
from analyzer.core.iteratorflow import ITERATOR, iterator_call


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('indices', [(0, 1), (1, 0), (0, 2), (0, 0), (2, 2)])
def test_swap_slots_aliases_and_path_isolation(ranged, indices):
    first = Trace('first', (), True, True)
    last = Trace('last', (), True)
    original = (first, None, last)
    obj = ObjectValue(ARRAYLIST, list_items=original)
    identity = ('allocation', 1)
    previous = Memory(refs={0: identity, 4: identity}, objects={identity: obj},
                      constants={1: indices[0], 2: indices[1]})
    changed, diagnostics = previous.copy(), []
    handled, returned = list_call(I(4, 'invoke-static' + ('/range' if ranged else ''), [0, 1, 2], target=SWAP),
                                  {}, changed, previous, 'test', diagnostics.append)
    assert handled and returned is None and not diagnostics
    assert changed.object(0) is changed.object(4) and previous.object(0) is obj
    assert previous.object(0).list_items == original
    expected = list(original)
    a, b = indices
    expected[a], expected[b] = expected[b], expected[a]
    for index, value in enumerate(expected):
        actual = changed.object(0).list_items[index]
        if value is None:
            assert actual is None
        else:
            assert actual.source == value.source and actual.uncertain == value.uncertain
            if a != b and index in indices:
                assert actual.steps[-1][2] == 'Collections.swap index %d -> %d' % (b if index == a else a, index)
            else:
                assert actual is value
    if a == b:
        assert changed.object(0) is obj


@pytest.mark.parametrize('case', ['negative', 'past_end', 'unknown', 'bool', 'empty', 'contents', 'budget', 'arity', 'opcode', 'receiver', 'other'])
def test_swap_unresolved_does_not_reuse_stale_contents(case, monkeypatch):
    obj = ObjectValue('Ljava/util/LinkedList;' if case == 'other' else ARRAYLIST,
                      list_items=None if case == 'contents' else () if case == 'empty' else (Trace('input', (), True), None))
    previous = Memory(refs={} if case == 'receiver' else {0: ('allocation', 1)},
                      objects={('allocation', 1): obj}, constants={1: 0, 2: 1})
    if case in ('negative', 'past_end', 'unknown', 'bool'):
        previous.constants[2] = {'negative': -1, 'past_end': 2, 'unknown': None, 'bool': True}[case]
    if case == 'budget':
        monkeypatch.setattr('analyzer.core.listflow.MAX_LIST_ITEMS', 1)
    changed, diagnostics = previous.copy(), []
    handled, returned = list_call(I(0, 'invoke-virtual' if case == 'opcode' else 'invoke-static',
        [0, 1] if case == 'arity' else [0, 1, 2], target=SWAP), {}, changed, previous, 'test', diagnostics.append)
    assert handled and returned is None and diagnostics
    assert previous.objects[('allocation', 1)] is obj
    if case not in ('receiver', 'other'):
        assert changed.object(0).list_items is None


def test_swap_invalidates_old_iterator_snapshot_conservatively():
    source = ObjectValue(ARRAYLIST, list_items=(Trace('input', (), True), None))
    previous = Memory(refs={0: 'list', 3: 'iterator'}, constants={1: 0, 2: 1},
        objects={'list': source, 'iterator': ObjectValue(ITERATOR, iterator_ref='list', iterator_snapshot=source, iterator_index=0)})
    changed, diagnostics = previous.copy(), []
    list_call(I(0, 'invoke-static', [0, 1, 2], target=SWAP), {}, changed, previous, 'test', diagnostics.append)
    after = changed.copy()
    _, result = iterator_call(I(2, 'invoke-interface', [3], target=ITERATOR + '->next()Ljava/lang/Object;'),
                              after, changed, 'test', diagnostics.append)
    assert result is None and diagnostics and after.object(3).iterator_index is None
