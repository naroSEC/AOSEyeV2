import pytest
from analyzer.core.arrayflow import ARRAYCOPY, copy_call
from analyzer.core.objectflow import Memory, ObjectValue
from analyzer.core.dataflow import Trace
from analyzer.core.models import Instruction


def setup(overlap=False):
    trace = Trace('input', (), True)
    objects = {('a',): ObjectValue('[Ljava/lang/String;', array_length=3,
                                 array_elements={0: trace, 1: None, 2: None}),
               ('b',): ObjectValue('[Ljava/lang/String;', array_length=3)}
    previous = Memory(refs={0: ('a',), 2: ('a',) if overlap else ('b',)},
                      constants={1: 0, 3: 1 if overlap else 0, 4: 2}, objects=objects)
    return previous, previous.copy(), Instruction(8, 'invoke-static', [0, 1, 2, 3, 4], target=ARRAYCOPY)


def test_copy_keeps_source_and_path_siblings():
    previous, memory, ins = setup()
    sibling = previous.copy()
    assert copy_call(ins, memory, previous, 'test', pytest.fail)
    assert memory.object(2).array_elements[0].external
    assert memory.object(2).array_elements[1] is None
    assert previous.object(2).array_elements == sibling.object(2).array_elements == {}
    assert memory.object(0) == previous.object(0)


def test_overlapping_copy_uses_snapshot():
    previous, memory, ins = setup(True)
    copy_call(ins, memory, previous, 'test', pytest.fail)
    assert memory.object(2).array_elements[1].external
    assert memory.object(2).array_elements[2] is None


def test_safe_copy_overwrites_taint():
    previous, memory, ins = setup(True)
    previous.constants.update({1: 1, 3: 0, 4: 1})
    copy_call(ins, memory, previous, 'test', pytest.fail)
    assert memory.object(2).array_elements[0] is None


@pytest.mark.parametrize('case', ['unknown', 'negative', 'overflow', 'identity', 'type'])
def test_unresolved_destination_is_not_reused(case):
    previous, memory, ins = setup()
    if case == 'unknown':
        previous.constants.pop(4)
    elif case == 'negative':
        previous.constants[4] = -1
    elif case == 'overflow':
        previous.constants[4] = 4
    elif case == 'identity':
        previous.refs.pop(0)
    else:
        previous.objects[('a',)] = ObjectValue('[Ljava/lang/Object;', array_length=3)
    diagnostics = []
    assert copy_call(ins, memory, previous, 'test', diagnostics.append)
    assert diagnostics and memory.object(2).array_length is None


def test_zero_copy_and_unknown_source_slot():
    previous, memory, ins = setup()
    previous.constants[4] = 0
    copy_call(ins, memory, previous, 'test', pytest.fail)
    assert memory.object(2) == previous.object(2)
    previous.constants[4] = 1
    previous.objects[('a',)] = ObjectValue('[Ljava/lang/String;', array_length=3,
                                         array_elements={None: Trace('possible', (), True, True)})
    copy_call(ins, memory, previous, 'test', pytest.fail)
    assert memory.object(2).array_elements[0].uncertain
