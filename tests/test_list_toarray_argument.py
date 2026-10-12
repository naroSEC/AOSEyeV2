import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import LIST, COLLECTION, TO_ARRAY_ARGUMENT, list_call


def state(length=4, items=None, kind='[Ljava/lang/Object;'):
    incoming = Trace('input', (), True, True)
    tail = Trace('tail', (), True)
    return Memory(refs={0: ('allocation', 1), 1: ('allocation', 2), 2: ('allocation', 2)},
        objects={('allocation', 1): ObjectValue(ARRAYLIST, list_items=(incoming, None) if items is None else items),
                 ('allocation', 2): ObjectValue(kind, array_length=length,
                      array_elements={i: tail for i in range(length or 0)})}, sequence=2)


def convert(previous, owner=LIST, ranged=False):
    changed, diagnostics = previous.copy(), []
    changed.result_ref = None
    op = 'invoke-virtual' if owner == ARRAYLIST else 'invoke-interface'
    handled, result = list_call(I(10, op + ('/range' if ranged else ''), [0, 1], target=owner + '->' + TO_ARRAY_ARGUMENT),
                               {}, changed, previous, 'test', diagnostics.append)
    assert handled and result is None
    return changed, diagnostics


@pytest.mark.parametrize('owner', [ARRAYLIST, LIST, COLLECTION])
@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('length', [0, 1, 2, 4])
def test_allocate_or_reuse_and_tail(owner, ranged, length):
    previous = state(length)
    changed, diagnostics = convert(previous, owner, ranged)
    assert not diagnostics
    assert (changed.result_ref == previous.refs[1]) == (length >= 2)
    array = changed.objects[changed.result_ref]
    assert array.array_length == max(2, length)
    assert array.array_elements[0].source == 'input' and array.array_elements[0].uncertain
    assert array.array_elements[1] is None
    if length == 4:
        assert array.array_elements[2] is None
        assert array.array_elements[3].source == 'tail'
        assert changed.object(2) == array
    if length < 2:
        assert changed.object(1) == previous.object(1)
    assert previous.sequence == 2 and changed.object(0) == previous.object(0)


def test_wildcard_only_survives_in_untouched_tail():
    previous = state()
    previous.update(1, array_elements={None: Trace('wildcard', (), True)})
    changed, diagnostics = convert(previous)
    slots = changed.object(1).array_elements
    assert not diagnostics and None not in slots
    assert slots[0].source == 'input' and slots[1] is None and slots[2] is None
    assert slots[3].source == 'wildcard' and slots[3].uncertain


@pytest.mark.parametrize('length', [0, 3])
def test_empty_list_nulls_only_first_slot(length):
    previous = state(length, items=())
    changed, diagnostics = convert(previous)
    assert not diagnostics and changed.result_ref == previous.refs[1]
    if length:
        assert changed.object(1).array_elements[0] is None
        assert changed.object(1).array_elements[1].source == 'tail'


@pytest.mark.parametrize('case', ['unknown_contents', 'unknown_length', 'unknown_array', 'string_array', 'length_budget', 'object_budget'])
def test_unresolved_conversion_invalidates_destination(case, monkeypatch):
    previous = state(1 if case == 'object_budget' else 4)
    if case == 'unknown_contents':
        previous.update(0, list_items=None)
    elif case == 'unknown_length':
        previous.update(1, array_length=None)
    elif case == 'unknown_array':
        previous.refs.pop(1)
    elif case == 'string_array':
        previous.update(1, type='[Ljava/lang/String;')
    elif case == 'length_budget':
        monkeypatch.setattr('analyzer.core.arrayflow.MAX_ARRAY_LENGTH', 1)
    elif case == 'object_budget':
        monkeypatch.setattr('analyzer.core.arrayflow.MAX_ARRAY_OBJECTS', 1)
    changed, diagnostics = convert(previous)
    assert diagnostics and changed.result_ref is None
    if case != 'unknown_array':
        assert changed.object(1).array_length is None and not changed.object(1).array_elements
    assert changed.object(0) == previous.object(0)


def test_reuse_does_not_consume_allocation_budget(monkeypatch):
    monkeypatch.setattr('analyzer.core.arrayflow.MAX_ARRAY_OBJECTS', 1)
    previous = state(4)
    changed, diagnostics = convert(previous)
    assert not diagnostics and changed.result_ref == previous.refs[1] and changed.sequence == previous.sequence


@pytest.mark.parametrize('case', ['unknown_receiver', 'other_receiver', 'wrong_opcode', 'wrong_arity'])
def test_rejected_call_does_not_reuse_stale_array(case):
    previous = state()
    if case == 'unknown_receiver':
        previous.refs.pop(0)
    if case == 'other_receiver':
        previous.update(0, type='Ljava/util/LinkedList;')
    changed, diagnostics = previous.copy(), []
    ins = I(0, 'invoke-static' if case == 'wrong_opcode' else 'invoke-interface',
            [0, 1, 2] if case == 'wrong_arity' else [0, 1], target=LIST + '->' + TO_ARRAY_ARGUMENT)
    handled, result = list_call(ins, {}, changed, previous, 'test', diagnostics.append)
    assert handled and result is None and diagnostics and changed.result_ref is None
    assert changed.object(1).array_length is None and not changed.object(2).array_elements
    assert previous.object(1).array_length == 4
