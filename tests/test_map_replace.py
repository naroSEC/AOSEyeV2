import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import HASHMAP, ObjectValue, Memory
from analyzer.core.mapflow import MAP, REPLACE, map_call


@pytest.mark.parametrize('owner', [HASHMAP, MAP])
@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('case', ['old_input', 'new_input', 'absent', 'unknown_key', 'unknown_contents'])
def test_replace_membership_return_and_path_isolation(owner, ranged, case, monkeypatch):
    trace = Trace('input', (), True, True)
    items = {'key': trace if case == 'old_input' else None}
    if case == 'absent':
        items = {}
    if case == 'unknown_contents':
        items = None
    identity = ('allocation', 1)
    previous = Memory(refs={0: identity, 4: identity}, constants={} if case == 'unknown_key' else {1: 'key'},
        objects={identity: ObjectValue(HASHMAP, map_items=items)}, sequence=1)
    changed, diagnostics = previous.copy(), []
    monkeypatch.setattr('analyzer.core.mapflow.MAX_MAP_ITEMS', 1)
    opcode = 'invoke-interface' if owner == MAP else 'invoke-virtual'
    handled, returned = map_call(I(10, opcode + ('/range' if ranged else ''), [0, 1, 2],
        target=owner + '->' + REPLACE), {} if case == 'old_input' else {2: trace},
        changed, previous, 'test', diagnostics.append)
    assert handled and previous.object(0).map_items == items
    assert changed.object(0) is changed.object(4)
    assert bool(diagnostics) == (case in ('unknown_key', 'unknown_contents'))
    if case == 'old_input':
        assert returned.uncertain and returned.steps[-1][2] == 'HashMap replace previous value'
        assert changed.object(0).map_items == {'key': None}
    else:
        assert returned is None
    if case == 'new_input':
        stored = changed.object(0).map_items['key']
        assert stored.uncertain and stored.steps[-1][2] == 'HashMap replace'
        assert len(changed.object(0).map_items) == 1
    if case == 'absent':
        assert changed.object(0).map_items == {}
        assert changed.object(0) is previous.object(0)
    if case in ('unknown_key', 'unknown_contents'):
        assert changed.object(0).map_items is None


def test_conditional_replace_remains_unsupported():
    previous = Memory(refs={0: ('allocation', 1)},
        objects={('allocation', 1): ObjectValue(HASHMAP, map_items={'key': None})})
    changed, diagnostics = previous.copy(), []
    handled, returned = map_call(I(0, 'invoke-interface', [0, 1, 2, 3],
        target=MAP + '->replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z'),
        {}, changed, previous, 'test', diagnostics.append)
    assert handled and returned is None and diagnostics
    assert changed.object(0).map_items is None
    assert previous.object(0).map_items == {'key': None}
