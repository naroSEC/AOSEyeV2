import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import Trace
from analyzer.core.objectflow import HASHMAP, Memory, ObjectValue
from analyzer.core.mapflow import MAP, GET_DEFAULT, CONTAINS_KEY, map_call


def query(items, member, key='key', owner=MAP, ranged=False, default=None):
    previous = Memory(refs={0: ('allocation', 1)}, constants={1: key},
        objects={('allocation', 1): ObjectValue(HASHMAP, map_items=items)})
    changed, diagnostics = previous.copy(), []
    registers = [0] if member in ('size()I', 'isEmpty()Z') else [0, 1, 2] if member == GET_DEFAULT else [0, 1]
    op = 'invoke-virtual' if owner == HASHMAP else 'invoke-interface'
    handled, value = map_call(I(0, op + ('/range' if ranged else ''), registers, target=owner + '->' + member),
                             {2: default} if default else {}, changed, previous, 'test', diagnostics.append)
    assert handled and changed.object(0) == previous.object(0) and changed.result_ref is None
    return changed, value, diagnostics


@pytest.mark.parametrize('owner', [HASHMAP, MAP])
@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('case', ['mapped', 'safe_mapping', 'missing', 'safe_default', 'unknown_key', 'unknown_contents'])
def test_getdefault_selects_only_actual_branch(owner, ranged, case):
    source = Trace('mapped', (), True, True)
    default = Trace('default', (), True, True)
    items = {'key': source} if case == 'mapped' else {'key': None} if case == 'safe_mapping' else {}
    if case == 'unknown_contents':
        items = None
    changed, value, diagnostics = query(items, GET_DEFAULT, None if case == 'unknown_key' else 'key',
        owner, ranged, None if case == 'safe_default' else default)
    if case in ('mapped', 'missing'):
        assert not diagnostics and value.source == ('mapped' if case == 'mapped' else 'default') and value.uncertain
    else:
        assert value is None
        assert bool(diagnostics) == (case in ('unknown_key', 'unknown_contents'))
    assert changed.result_constant is None


@pytest.mark.parametrize('owner', [HASHMAP, MAP])
@pytest.mark.parametrize('items', [{}, {'key': None}, {'key': Trace('input', (), True)}, None])
def test_size_presence_empty(owner, items):
    for member in ('size()I', 'isEmpty()Z', CONTAINS_KEY):
        changed, value, diagnostics = query(items, member, owner=owner)
        assert value is None
        if items is None:
            assert diagnostics and changed.result_constant is None
        else:
            assert not diagnostics
            expected = len(items) if member == 'size()I' else int(not items) if member == 'isEmpty()Z' else int('key' in items)
            assert changed.result_constant == expected


def test_unknown_contains_key_preserves_contents():
    changed, value, diagnostics = query({'key': Trace('input', (), True)}, CONTAINS_KEY, key=None)
    assert diagnostics and value is None and changed.result_constant is None
