import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import ObjectValue, Memory
from analyzer.core.arrayflow import access


@pytest.mark.parametrize('index', [0, 1, 2])
@pytest.mark.parametrize('input_value', [False, True])
def test_known_store_replaces_wildcard_only_at_selected_slot(index, input_value):
    wildcard, value = Trace('prior', (), True), Trace('new', (), True)
    obj = ObjectValue('[Ljava/lang/Object;', array_length=3, array_elements={None: wildcard})
    previous = Memory(refs={1: 'array', 5: 'array'}, constants={2: index}, objects={'array': obj})
    changed, diagnostics = previous.copy(), []
    access(I(4, 'aput-object', [0, 1, 2]), {0: value} if input_value else {}, {}, changed, previous, 'test', diagnostics.append)
    assert not diagnostics and previous.object(1) is obj and changed.object(1) is changed.object(5)
    slots = changed.object(1).array_elements
    assert None not in slots
    for position in range(3):
        if position != index:
            assert slots[position].source == 'prior' and slots[position].uncertain
        elif input_value:
            assert slots[position].source == 'new' and not slots[position].uncertain
        else:
            assert slots[position] is None


def test_later_unknown_write_can_retaint_cleared_slot():
    obj = ObjectValue('[Ljava/lang/Object;', array_length=2, array_elements={None: Trace('old', (), True)})
    previous = Memory(refs={1: 'array'}, constants={2: 0}, objects={'array': obj})
    changed = previous.copy()
    access(I(0, 'aput-object', [0, 1, 2]), {}, {}, changed, previous, 'test', lambda _: None)
    after = changed.copy()
    access(I(2, 'aput-object', [0, 1, 3]), {0: Trace('new', (), True)}, {}, after, changed, 'test', lambda _: None)
    regs = {}
    access(I(4, 'aget-object', [4, 1, 2]), {}, regs, after.copy(), after, 'test', lambda _: None)
    assert regs[4].source == 'new' and regs[4].uncertain


def test_all_slots_overwritten_remove_all_old_flows():
    obj = ObjectValue('[Ljava/lang/Object;', array_length=2, array_elements={None: Trace('old', (), True)})
    previous = Memory(refs={1: 'array'}, constants={2: 0}, objects={'array': obj})
    for index in range(2):
        previous.constants[2] = index
        changed = previous.copy()
        access(I(index, 'aput-object', [0, 1, 2]), {}, {}, changed, previous, 'test', lambda _: None)
        previous = changed
    assert previous.object(1).array_elements == {0: None, 1: None}
