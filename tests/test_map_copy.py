import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import HASHMAP, Memory, ObjectValue
from analyzer.core.mapflow import MAP, PUT_ALL, COPY_INIT, map_call


def state():
    return Memory(refs={0: ('allocation', 1), 1: ('allocation', 2), 2: ('allocation', 1)}, sequence=2,
        objects={('allocation', 1): ObjectValue(HASHMAP, map_items={'overlap': Trace('old', (), True), 'retained': None}),
                 ('allocation', 2): ObjectValue(HASHMAP, map_items={'overlap': None, 'input': Trace('input', (), True, True)})})


def copy(previous, member=PUT_ALL, owner=MAP, ranged=False):
    changed, diagnostics = previous.copy(), []
    op = 'invoke-direct' if member == COPY_INIT else 'invoke-interface' if owner == MAP else 'invoke-virtual'
    handled, result = map_call(I(10, op + ('/range' if ranged else ''), [0, 1], target=owner + '->' + member),
                               {}, changed, previous, 'test', diagnostics.append)
    assert handled and result is None and changed.result_ref is None and changed.result_constant is None
    return changed, diagnostics


@pytest.mark.parametrize('member,owner', [(PUT_ALL, MAP), (PUT_ALL, HASHMAP), (COPY_INIT, HASHMAP)])
@pytest.mark.parametrize('ranged', [False, True])
def test_copy_overwrite_alias_and_independence(member, owner, ranged):
    previous = state()
    if member == COPY_INIT:
        previous.update(0, map_items=None)
    changed, diagnostics = copy(previous, member, owner, ranged)
    assert not diagnostics and changed.object(0) == changed.object(2)
    items = changed.object(0).map_items
    assert items['overlap'] is None and items['input'].source == 'input' and items['input'].uncertain
    assert ('retained' in items) == (member == PUT_ALL)
    changed.update(1, map_items={})
    assert changed.object(0).map_items['input'].source == 'input'
    assert previous.object(1).map_items['input'].source == 'input'
    if member == PUT_ALL:
        assert previous.object(0).map_items['overlap'].source == 'old'


@pytest.mark.parametrize('member', [PUT_ALL, COPY_INIT])
@pytest.mark.parametrize('case', ['empty', 'unknown', 'other', 'self', 'contents', 'budget'])
def test_copy_limits_and_unknowns(member, case, monkeypatch):
    previous = state()
    if case == 'empty':
        previous.update(1, map_items={})
    elif case == 'unknown':
        previous.refs.pop(1)
    elif case == 'other':
        previous.update(1, type='Ljava/util/TreeMap;')
    elif case == 'self':
        previous.refs[1] = previous.refs[0]
    elif case == 'contents':
        previous.update(1, map_items=None)
    elif case == 'budget':
        monkeypatch.setattr('analyzer.core.mapflow.MAX_MAP_ITEMS', 1)
    changed, diagnostics = copy(previous, member, HASHMAP)
    if case == 'empty':
        assert not diagnostics
        assert changed.object(0).map_items == ({} if member == COPY_INIT else previous.object(0).map_items)
    else:
        assert diagnostics and changed.object(0).map_items is None
    if case != 'self':
        assert changed.object(1) == previous.object(1)


def test_overlap_counts_unique_keys_at_budget(monkeypatch):
    previous = state()
    monkeypatch.setattr('analyzer.core.mapflow.MAX_MAP_ITEMS', 3)
    changed, diagnostics = copy(previous)
    assert not diagnostics and len(changed.object(0).map_items) == 3


def test_unknown_destination_putall_is_not_recovered():
    previous = state()
    previous.update(0, map_items=None)
    changed, diagnostics = copy(previous)
    assert diagnostics and changed.object(0).map_items is None


def test_interface_constructor_rejected():
    changed, diagnostics = copy(state(), COPY_INIT, MAP)
    assert diagnostics and changed.object(0).map_items is None
