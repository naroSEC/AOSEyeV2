import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ObjectValue, Memory
from analyzer.core.arrayflow import FILL_RANGE, fill_call


def invoke(previous, old=None, ranged=False, registers=None, opcode=None):
    changed, diagnostics = previous.copy(), []
    assert fill_call(I(4, opcode or ('invoke-static' + ('/range' if ranged else '')),
        [0, 1, 2, 3] if registers is None else registers, target=FILL_RANGE), old or {}, changed, previous, 'test', diagnostics.append)
    return changed, diagnostics


@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('bounds', [(0, 0), (3, 3), (0, 1), (1, 2), (2, 3), (0, 3)])
@pytest.mark.parametrize('input_value', [False, True])
def test_fill_range_preserves_outside_and_isolates_paths(ranged, bounds, input_value):
    prior, value = Trace('prior', (), True), Trace('new', (), True, True)
    obj = ObjectValue('[Ljava/lang/Object;', array_length=3, array_elements={i: prior for i in range(3)})
    previous = Memory(refs={0: 'array', 5: 'array'}, constants={1: bounds[0], 2: bounds[1]}, objects={'array': obj})
    changed, diagnostics = invoke(previous, {3: value} if input_value else {}, ranged)
    assert not diagnostics and previous.object(0) is obj and changed.object(0) is changed.object(5)
    assert changed.object(0).array_length == 3
    if bounds[0] == bounds[1]:
        assert changed.object(0) is obj
    for index in range(3):
        actual = changed.object(0).array_elements[index]
        if not bounds[0] <= index < bounds[1]:
            assert actual is prior
        elif input_value:
            assert actual.source == 'new' and actual.uncertain
            assert actual.steps[-1][2] == 'Arrays.fill range index ' + str(index)
        else:
            assert actual is None


def test_wildcard_survives_only_outside_written_range():
    obj = ObjectValue('[Ljava/lang/Object;', array_length=3, array_elements={None: Trace('input', (), True)})
    previous = Memory(refs={0: 'array'}, constants={1: 1, 2: 2}, objects={'array': obj})
    changed, diagnostics = invoke(previous)
    assert not diagnostics and None not in changed.object(0).array_elements
    slots = changed.object(0).array_elements
    assert slots[1] is None and all(slots[i].uncertain and slots[i].source == 'input' for i in (0, 2))
    changed.constants.update({1: 0, 2: 3})
    cleared, diagnostics = invoke(changed)
    assert not diagnostics and all(v is None for v in cleared.object(0).array_elements.values())


@pytest.mark.parametrize('bounds', [(-1, 1), (2, 1), (0, 4), (None, 2), (0, None), (True, 2), (0, 1.0), (4, 4)])
def test_invalid_bounds_invalidate_contents(bounds):
    obj = ObjectValue('[Ljava/lang/Object;', array_length=3, array_elements={0: Trace('old', (), True)})
    previous = Memory(refs={0: 'array'}, constants={1: bounds[0], 2: bounds[1]}, objects={'array': obj})
    changed, diagnostics = invoke(previous)
    assert diagnostics and changed.object(0).array_length is None and previous.object(0) is obj


@pytest.mark.parametrize('case', ['arity', 'opcode', 'nested', 'type', 'budget'])
def test_range_failure_contract(case):
    obj = ObjectValue('[Ljava/lang/String;' if case == 'type' else '[Ljava/lang/Object;', array_length=65 if case == 'budget' else 3)
    previous = Memory(refs={0: 'array'}, constants={1: 0, 2: 1}, objects={'array': obj})
    if case == 'nested':
        previous.refs[3] = 'array'
    changed, diagnostics = invoke(previous, registers=[0, 1, 2] if case == 'arity' else None,
                                  opcode='invoke-virtual' if case == 'opcode' else None)
    assert diagnostics and changed.object(0).array_length is None and previous.object(0) is obj


def test_empty_array_empty_range_noop():
    obj = ObjectValue('[Ljava/lang/Object;', array_length=0)
    previous = Memory(refs={0: 'array', 3: 'array'}, constants={1: 0, 2: 0}, objects={'array': obj})
    changed, diagnostics = invoke(previous)
    assert not diagnostics and changed.object(0) is obj
