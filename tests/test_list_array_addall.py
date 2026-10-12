import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue, Memory
from analyzer.core.listflow import ADD_ALL_ARRAY, list_call


def invoke(previous, ranged=False, registers=None, opcode=None):
    changed, diagnostics = previous.copy(), []
    handled, value = list_call(I(4, opcode or ('invoke-static' + ('/range' if ranged else '')),
        [0, 1] if registers is None else registers, target=ADD_ALL_ARRAY), {}, changed, previous, 'test', diagnostics.append)
    assert handled and value is None
    return changed, diagnostics


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('kind', ['[Ljava/lang/String;', '[Ljava/lang/Object;'])
@pytest.mark.parametrize('count', [0, 1, 3, 63])
def test_array_append_order_prefix_and_independence(ranged, kind, count):
    old, value = Trace('old', (), True), Trace('new', (), True, True)
    source = ObjectValue(kind, array_length=count, array_elements={0: value})
    dest = ObjectValue(ARRAYLIST, list_items=(old,))
    previous = Memory(refs={0: 'dest', 1: 'source', 5: 'dest'}, objects={'dest': dest, 'source': source})
    changed, diagnostics = invoke(previous, ranged)
    assert not diagnostics and changed.result_constant == int(count != 0)
    assert changed.object(0) is changed.object(5) and previous.object(0) is dest
    assert changed.object(1) is source and len(changed.object(0).list_items) == 1 + count
    assert changed.object(0).list_items[0] is old
    if count:
        copied = changed.object(0).list_items[1]
        assert copied.source == 'new' and copied.uncertain
        assert copied.steps[-1][2] == 'Collections.addAll array index 0 -> 1'
        assert changed.object(0).list_items[2:] == (None,) * (count - 1)
        changed.update(1, array_elements={0: None})
        assert changed.object(0).list_items[1] is copied
    else:
        assert changed.object(0) is dest


def test_wildcard_external_trace_is_uncertain_not_safe():
    source = ObjectValue('[Ljava/lang/Object;', array_length=2,
        array_elements={0: Trace('local', (), False), None: Trace('input', (), True)})
    previous = Memory(refs={0: 'dest', 1: 'source'}, objects={
        'dest': ObjectValue(ARRAYLIST, list_items=()), 'source': source})
    changed, diagnostics = invoke(previous)
    assert not diagnostics
    assert all(v.source == 'input' and v.uncertain for v in changed.object(0).list_items)


@pytest.mark.parametrize('case', ['dest_contents', 'length', 'negative', 'bool', 'array_budget', 'list_budget',
    'no_args', 'extra_args', 'opcode', 'source_missing', 'dest_missing', 'primitive', 'other_dest'])
def test_invalid_append_does_not_leave_stale_destination(case):
    dest = ObjectValue('Ljava/util/LinkedList;' if case == 'other_dest' else ARRAYLIST,
        list_items=None if case == 'dest_contents' else (None,) * (64 if case == 'list_budget' else 1))
    length = {'length': None, 'negative': -1, 'bool': True, 'array_budget': 65}.get(case, 1)
    source = ObjectValue('[I' if case == 'primitive' else '[Ljava/lang/String;', array_length=length)
    previous = Memory(refs={0: 'dest', 1: 'source'}, objects={'dest': dest, 'source': source})
    if case.endswith('_missing'):
        previous.refs.pop(0 if case == 'dest_missing' else 1)
    changed, diagnostics = invoke(previous, registers=[] if case == 'no_args' else [0, 1, 2] if case == 'extra_args' else None,
                                  opcode='invoke-virtual' if case == 'opcode' else None)
    assert diagnostics and changed.result_constant is None
    assert previous.objects['dest'] is dest and changed.objects['source'] is source
    if case not in ('no_args', 'dest_missing', 'other_dest'):
        assert changed.object(0).list_items is None
