import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import LIST, COLLECTION, list_call
from analyzer.core.iteratorflow import ITERATOR, ITERABLE, CREATE


def invoke(previous, owner, member, register, ranged=False):
    changed, diagnostics = previous.copy(), []
    changed.result_ref = changed.result_constant = None
    opcode = 'invoke-virtual' if owner == ARRAYLIST else 'invoke-interface'
    handled, value = list_call(I(10, opcode + ('/range' if ranged else ''), [register], target=owner + '->' + member),
                              {}, changed, previous, 'test', diagnostics.append)
    assert handled
    return changed, value, diagnostics


def initial(items=(Trace('input', (), True, True), None)):
    return Memory(refs={0: ('allocation', 1)}, objects={('allocation', 1): ObjectValue(ARRAYLIST, list_items=items)}, sequence=1)


def iterator(previous, owner=LIST, ranged=False):
    changed, _, diagnostics = invoke(previous, owner, CREATE, 0, ranged)
    if changed.result_ref:
        changed.refs[1] = changed.result_ref
        changed.refs[2] = changed.result_ref
    return changed, diagnostics


@pytest.mark.parametrize('owner', [ARRAYLIST, LIST, COLLECTION, ITERABLE])
@pytest.mark.parametrize('ranged', [False, True])
def test_order_alias_cursor_and_path_isolation(owner, ranged):
    previous, diagnostics = iterator(initial(), owner, ranged)
    assert not diagnostics
    checked, _, diagnostics = invoke(previous, ITERATOR, 'hasNext()Z', 1, ranged)
    assert not diagnostics and checked.result_constant == 1 and checked.object(1).iterator_index == 0
    first, value, diagnostics = invoke(checked, ITERATOR, 'next()Ljava/lang/Object;', 2, ranged)
    assert not diagnostics and value.source == 'input' and value.uncertain
    assert first.object(1).iterator_index == 1 and previous.object(1).iterator_index == 0
    second, value, diagnostics = invoke(first, ITERATOR, 'next()Ljava/lang/Object;', 1, ranged)
    assert not diagnostics and value is None and second.object(2).iterator_index == 2
    end, _, diagnostics = invoke(second, ITERATOR, 'hasNext()Z', 1, ranged)
    assert not diagnostics and end.result_constant == 0
    _, value, diagnostics = invoke(end, ITERATOR, 'next()Ljava/lang/Object;', 1, ranged)
    assert value is None and diagnostics


def test_two_iterators_have_independent_positions():
    first, _ = iterator(initial())
    second, _, diagnostics = invoke(first, LIST, CREATE, 0)
    second.refs[3] = second.result_ref
    moved, _, _ = invoke(second, ITERATOR, 'next()Ljava/lang/Object;', 1)
    assert not diagnostics and moved.object(1).iterator_index == 1 and moved.object(3).iterator_index == 0


@pytest.mark.parametrize('case', ['clear', 'set', 'unknown', 'unsupported'])
def test_changed_source_or_unsupported_call_never_reuses_old_elements(case):
    previous, _ = iterator(initial())
    if case == 'clear':
        previous.update(0, list_items=())
    elif case == 'set':
        previous.update(0, list_items=(None, None))
    elif case == 'unknown':
        previous.objects.pop(previous.refs[0])
    else:
        previous, _, diagnostics = invoke(previous, ITERATOR, 'forEachRemaining(Ljava/util/function/Consumer;)V', 1)
        assert diagnostics and previous.object(0).list_items is None
    changed, value, diagnostics = invoke(previous, ITERATOR, 'next()Ljava/lang/Object;', 1)
    assert value is None and diagnostics and changed.object(1).iterator_index is None


@pytest.mark.parametrize('case', ['empty', 'unknown', 'budget'])
def test_empty_unknown_and_budget(case, monkeypatch):
    previous = initial(None if case == 'unknown' else ())
    if case == 'budget':
        monkeypatch.setattr('analyzer.core.iteratorflow.MAX_ITERATORS', 0)
    changed, diagnostics = iterator(previous)
    if case == 'empty':
        assert not diagnostics
        end, _, diagnostics = invoke(changed, ITERATOR, 'hasNext()Z', 1)
        assert not diagnostics and end.result_constant == 0
    else:
        assert diagnostics and changed.result_ref is None


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('remove_index', [0, 1, 2])
def test_remove_cursor_shift_alias_and_other_iterator(ranged, remove_index):
    values = tuple(Trace('input' + str(n), (), True, True) for n in range(3))
    previous, _ = iterator(initial(values))
    previous, _, _ = invoke(previous, LIST, CREATE, 0)
    previous.refs[3] = previous.result_ref
    previous.refs[4] = previous.refs[0]
    for _ in range(remove_index + 1):
        previous, _, _ = invoke(previous, ITERATOR, 'next()Ljava/lang/Object;', 1, ranged)
    before = previous
    checked, _, _ = invoke(previous, ITERATOR, 'hasNext()Z', 2, ranged)
    removed, value, diagnostics = invoke(checked, ITERATOR, 'remove()V', 2, ranged)
    assert not diagnostics and value is None
    assert removed.object(1).iterator_index == remove_index and removed.object(1).iterator_last is None
    assert len(removed.object(4).list_items) == 2 and len(before.object(0).list_items) == 3
    assert all(v.source != 'input' + str(remove_index) for v in removed.object(0).list_items)
    if remove_index < 2:
        next_state, value, diagnostics = invoke(removed, ITERATOR, 'next()Ljava/lang/Object;', 1, ranged)
        assert not diagnostics and value.source == 'input' + str(remove_index + 1) and value.uncertain
        assert any('iterator remove shift' in step[2] for step in value.steps)
    else:
        next_state, _, diagnostics = invoke(removed, ITERATOR, 'hasNext()Z', 1, ranged)
        assert not diagnostics and next_state.result_constant == 0
    _, value, diagnostics = invoke(removed, ITERATOR, 'next()Ljava/lang/Object;', 3)
    assert value is None and diagnostics  # Other iterator keeps the old snapshot.


@pytest.mark.parametrize('case', ['before_next', 'twice', 'changed_source'])
def test_remove_invalid_order_preserves_source(case):
    previous, _ = iterator(initial())
    if case != 'before_next':
        previous, _, _ = invoke(previous, ITERATOR, 'next()Ljava/lang/Object;', 1)
    if case == 'twice':
        previous, _, _ = invoke(previous, ITERATOR, 'remove()V', 1)
    if case == 'changed_source':
        previous.update(0, list_items=())
    changed, value, diagnostics = invoke(previous, ITERATOR, 'remove()V', 1)
    assert diagnostics and value is None and changed.object(0) == previous.object(0)
    assert changed.object(1).iterator_index is None


def test_remove_safe_element_advances_correctly_and_can_remove_again():
    previous, _ = iterator(initial((None, Trace('input', (), True))))
    previous, value, _ = invoke(previous, ITERATOR, 'next()Ljava/lang/Object;', 1)
    assert value is None
    previous, _, diagnostics = invoke(previous, ITERATOR, 'remove()V', 1)
    assert not diagnostics
    previous, value, diagnostics = invoke(previous, ITERATOR, 'next()Ljava/lang/Object;', 1)
    assert not diagnostics and value.source == 'input'
    previous, _, diagnostics = invoke(previous, ITERATOR, 'remove()V', 1)
    assert not diagnostics and previous.object(0).list_items == ()
