import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ObjectValue, Memory
from analyzer.core.arrayflow import FILL, fill_call


def invoke(previous, old=None, ranged=False, registers=None, opcode=None):
    changed, diagnostics = previous.copy(), []
    assert fill_call(I(4, opcode or ('invoke-static' + ('/range' if ranged else '')),
        [0, 1] if registers is None else registers, target=FILL), old or {}, changed, previous, 'test', diagnostics.append)
    return changed, diagnostics


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('length', [0, 1, 3, 64])
@pytest.mark.parametrize('input_value', [False, True])
def test_fill_replaces_all_slots_and_wildcard(ranged, length, input_value):
    old, value = Trace('old', (), True, True), Trace('new', (), True, True)
    obj = ObjectValue('[Ljava/lang/Object;', array_length=length, array_elements={0: old, None: old} if length else {})
    previous = Memory(refs={0: 'array', 5: 'array'}, objects={'array': obj})
    changed, diagnostics = invoke(previous, {1: value} if input_value else {}, ranged)
    assert not diagnostics and previous.object(0) is obj
    assert changed.object(0) is changed.object(5) and changed.object(0).array_length == length
    assert None not in changed.object(0).array_elements
    assert set(changed.object(0).array_elements) == set(range(length))
    if not length:
        assert changed.object(0) is obj
    for index, trace in changed.object(0).array_elements.items():
        if input_value:
            assert trace.source == 'new' and trace.uncertain
            assert trace.steps[-1][2] == 'Arrays.fill index ' + str(index)
        else:
            assert trace is None
    cleared, diagnostics = invoke(changed)
    assert not diagnostics and all(value is None for value in cleared.object(0).array_elements.values())


@pytest.mark.parametrize('case', ['unknown', 'negative', 'bool', 'budget', 'no_args', 'extra_args', 'opcode',
    'missing', 'string_array', 'primitive', 'nested', 'self'])
def test_fill_unresolved_invalidates_array(case):
    kind = '[Ljava/lang/String;' if case == 'string_array' else '[I' if case == 'primitive' else '[Ljava/lang/Object;'
    length = {'unknown': None, 'negative': -1, 'bool': True, 'budget': 65}.get(case, 2)
    obj = ObjectValue(kind, array_length=length, array_elements={0: Trace('input', (), True)})
    previous = Memory(refs={} if case == 'missing' else {0: 'array'}, objects={'array': obj})
    if case in ('nested', 'self'):
        previous.refs[1] = 'array' if case == 'self' else 'nested'
        previous.objects['nested'] = ObjectValue('Ljava/lang/Object;')
    changed, diagnostics = invoke(previous, registers=[] if case == 'no_args' else [0, 1, 2] if case == 'extra_args' else None,
                                  opcode='invoke-virtual' if case == 'opcode' else None)
    assert diagnostics and previous.objects['array'] is obj
    if case not in ('missing', 'no_args'):
        assert changed.object(0).array_length is None and changed.object(0).array_elements == {}


def test_empty_fill_does_not_store_self_reference():
    obj = ObjectValue('[Ljava/lang/Object;', array_length=0)
    previous = Memory(refs={0: 'array', 1: 'array'}, objects={'array': obj})
    changed, diagnostics = invoke(previous)
    assert not diagnostics and changed.object(0) is obj
