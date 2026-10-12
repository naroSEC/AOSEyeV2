import pytest
from analyzer.app.jobs import Cancellation
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import FlowEngine, Trace
from analyzer.core.rules.registry import RuleRegistry
from analyzer.core.objectflow import HASHMAP, Memory, ObjectValue
from analyzer.core.mapflow import MAP, PUT, GET, REMOVE, map_call
from conftest import method, SINK
from test_arrayflow import ENTRY


@pytest.mark.parametrize('owner', [HASHMAP, MAP])
@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('case', ['normal', 'alias', 'missing', 'overwrite', 'put_return', 'remove', 'remove_return', 'clear', 'unknown', 'budget'])
def test_map_pipeline(owner, ranged, case, monkeypatch):
    if case == 'budget':
        monkeypatch.setattr('analyzer.core.mapflow.MAX_MAP_ITEMS', 0)
    code = []
    def emit(op, registers, **kw):
        code.append(I(len(code) * 2, op, registers, **kw))
    def call(member, registers):
        emit(('invoke-virtual' if owner == HASHMAP else 'invoke-interface') + ('/range' if ranged else ''),
             registers, target=owner + '->' + member)
    emit('new-instance', [4], defs=[4], literal=HASHMAP)
    emit('invoke-direct', [4], target=HASHMAP + '-><init>()V')
    emit('const-string', [5], defs=[5], literal='key')
    emit('const-string', [6], defs=[6], literal='safe')
    call(PUT, [4, 5, 1])
    if case == 'alias':
        emit('move-object', [7, 4], defs=[7])
        receiver = 7
    else:
        receiver = 4
    if case in ('overwrite', 'put_return'):
        call(PUT, [receiver, 5, 6])
    if case in ('remove', 'remove_return'):
        call(REMOVE, [receiver, 5])
    if case == 'clear':
        call('clear()V', [receiver])
    if case == 'missing':
        emit('const-string', [5], defs=[5], literal='absent')
    if case == 'unknown':
        emit('move-object', [5, 1], defs=[5])
    if case not in ('put_return', 'remove_return'):
        call(GET, [receiver, 5])
    emit('move-result-object', [8], defs=[8])
    emit('invoke-virtual', [9, 8], target=SINK)
    emit('return-object', [8])
    flows, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 3])}), {ENTRY}, Cancellation())
    assert bool(flows) == (case in ('normal', 'alias', 'put_return', 'remove_return'))
    if flows:
        assert flows[0].verification == 'LIKELY'
    if case in ('unknown', 'budget'):
        assert diagnostics


@pytest.mark.parametrize('member', [PUT, REMOVE])
def test_unknown_mutation_invalidates_path_local_contents(member):
    previous = Memory(refs={0: ('allocation', 1)}, objects={('allocation', 1): ObjectValue(HASHMAP, map_items={'a': Trace('input', (), True)})})
    changed, diagnostics = previous.copy(), []
    map_call(I(0, 'invoke-interface', [0, 1, 2] if member == PUT else [0, 1], target=MAP + '->' + member),
             {}, changed, previous, 'test', diagnostics.append)
    assert diagnostics and changed.object(0).map_items is None and previous.object(0).map_items['a']


@pytest.mark.parametrize('opcode', ['invoke-static', 'invoke-virtual'])
def test_map_through_local_call(opcode):
    helper = 'Ltest/Helper;->read(Ljava/util/Map;)Ljava/lang/String;'
    entry = method(ENTRY, [I(0, 'new-instance', [4], defs=[4], literal=HASHMAP),
        I(2, 'invoke-direct', [4], target=HASHMAP + '-><init>()V'),
        I(4, 'const-string', [5], defs=[5], literal='key'),
        I(6, 'invoke-interface', [4, 5, 1], target=MAP + '->' + PUT),
        I(8, opcode, [4] if opcode == 'invoke-static' else [9, 4], target=helper),
        I(10, 'move-result-object', [8], defs=[8]), I(12, 'invoke-virtual', [9, 8], target=SINK),
        I(14, 'return-object', [8])], [0, 1, 2, 3])
    callee = method(helper, [I(0, 'const-string', [2], defs=[2], literal='key'),
        I(2, 'invoke-interface', [1, 2], target=MAP + '->' + GET),
        I(4, 'move-result-object', [3], defs=[3]), I(6, 'return-object', [3])],
        [1] if opcode == 'invoke-static' else [0, 1])
    flows, _ = FlowEngine(RuleRegistry()).analyze(Program(methods={ENTRY: entry, helper: callee}), {ENTRY}, Cancellation())
    assert flows[0].verification == ('LIKELY' if opcode == 'invoke-static' else 'POTENTIAL')


@pytest.mark.parametrize('descriptor', [None, 'Ljava/util/TreeMap;', 'Ltest/CustomMap;'])
def test_unknown_or_other_receiver_not_treated_as_hashmap(descriptor):
    previous = Memory() if descriptor is None else Memory(refs={0: ('allocation', 1)},
        objects={('allocation', 1): ObjectValue(descriptor, map_items={'key': Trace('input', (), True)})})
    previous.constants[1] = 'key'
    diagnostics = []
    handled, value = map_call(I(0, 'invoke-interface', [0, 1], target=MAP + '->' + GET),
                             {}, previous.copy(), previous, 'test', diagnostics.append)
    assert handled and value is None and diagnostics


def test_entry_limit_allows_replacement_and_unsupported_call_invalidates(monkeypatch):
    monkeypatch.setattr('analyzer.core.mapflow.MAX_MAP_ITEMS', 1)
    trace = Trace('input', (), True, True)
    previous = Memory(refs={0: ('allocation', 1)}, constants={1: 'key'},
        objects={('allocation', 1): ObjectValue(HASHMAP, map_items={'key': trace})})
    changed, diagnostics = previous.copy(), []
    _, value = map_call(I(0, 'invoke-interface', [0, 1, 2], target=MAP + '->' + PUT),
                       {}, changed, previous, 'test', diagnostics.append)
    assert not diagnostics and value.uncertain and changed.object(0).map_items == {'key': None}
    assert previous.object(0).map_items['key'] == trace
    other = changed.copy()
    map_call(I(2, 'invoke-interface', [0], target=MAP + '->entrySet()Ljava/util/Set;'),
             {}, other, changed, 'test', diagnostics.append)
    assert diagnostics and other.object(0).map_items is None


def test_map_allocation_budget(monkeypatch):
    monkeypatch.setattr('analyzer.core.mapflow.MAX_MAP_OBJECTS', 0)
    code = [I(0, 'new-instance', [4], defs=[4], literal=HASHMAP), I(2, 'return-void', [])]
    flows, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 3])}), {ENTRY}, Cancellation())
    assert not flows and any('HashMap allocation budget' in message for message in diagnostics)
