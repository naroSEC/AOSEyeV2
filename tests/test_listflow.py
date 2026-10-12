import pytest
from analyzer.app.jobs import Cancellation
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import FlowEngine, Trace
from analyzer.core.rules.registry import RuleRegistry
from analyzer.core.objectflow import ARRAYLIST, Memory, ObjectValue
from analyzer.core.listflow import list_call, LIST, COLLECTION
from conftest import method, SINK
from test_arrayflow import ENTRY


@pytest.mark.parametrize('case', ['normal', 'alias', 'other', 'clear', 'set', 'set_return', 'unknown', 'unsupported', 'budget'])
@pytest.mark.parametrize('owner', [ARRAYLIST, LIST, COLLECTION])
@pytest.mark.parametrize('ranged', [False, True])
def test_list_pipeline(case, owner, ranged, monkeypatch):
    if case == 'budget':
        monkeypatch.setattr('analyzer.core.listflow.MAX_LIST_ITEMS', 0)
    code = []
    def emit(op, registers, **kw):
        if op == 'invoke-virtual' and kw.get('target', '').startswith(ARRAYLIST + '->'):
            member = kw['target'].split('->')[1]
            actual_owner = LIST if owner == COLLECTION and member not in ('clear()V', 'add(Ljava/lang/Object;)Z') else owner
            kw['target'] = actual_owner + '->' + member
            op = 'invoke-virtual' if actual_owner == ARRAYLIST else 'invoke-interface'
            if ranged:
                op += '/range'
        code.append(I(len(code) * 2, op, registers, **kw))
    emit('new-instance', [4], defs=[4], literal=ARRAYLIST)
    emit('invoke-direct', [4], target=ARRAYLIST + '-><init>()V')
    emit('invoke-virtual', [4, 1], target=ARRAYLIST + '->add(Ljava/lang/Object;)Z')
    emit('const/4', [5], defs=[5], literal=None if case == 'unknown' else 0)
    emit('const-string', [6], defs=[6], literal='safe')
    receiver = 4
    if case == 'alias':
        emit('move-object', [7, 4], defs=[7])
        receiver = 7
    elif case == 'other':
        emit('new-instance', [7], defs=[7], literal=ARRAYLIST)
        emit('invoke-direct', [7], target=ARRAYLIST + '-><init>()V')
        emit('invoke-virtual', [7, 6], target=ARRAYLIST + '->add(Ljava/lang/Object;)Z')
        receiver = 7
    elif case == 'clear':
        emit('invoke-virtual', [4], target=ARRAYLIST + '->clear()V')
        emit('invoke-virtual', [4, 6], target=ARRAYLIST + '->add(Ljava/lang/Object;)Z')
    elif case in ('set', 'set_return'):
        emit('invoke-virtual', [4, 5, 6], target=ARRAYLIST + '->set(ILjava/lang/Object;)Ljava/lang/Object;')
    elif case == 'unsupported':
        emit('invoke-virtual', [4, 6], target=ARRAYLIST + '->remove(Ljava/lang/Object;)Z')
    if case != 'set_return':
        emit('invoke-virtual', [receiver, 5], target=ARRAYLIST + '->get(I)Ljava/lang/Object;')
    emit('move-result-object', [8], defs=[8])
    emit('invoke-virtual', [9, 8], target=SINK)
    emit('return-object', [8])
    flows, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 3])}), {ENTRY}, Cancellation())
    assert bool(flows) == (case in ('normal', 'alias', 'set_return'))
    if flows:
        assert flows[0].verification == 'LIKELY'
    if case in ('unknown', 'unsupported', 'budget'):
        assert diagnostics


@pytest.mark.parametrize('owner', [ARRAYLIST, LIST])
def test_path_local_list_and_uncertain_trace(owner):
    trace = Trace('possible', (), True, True)
    previous = Memory(refs={0: ('allocation', 1)}, constants={1: 0},
        objects={('allocation', 1): ObjectValue(ARRAYLIST, list_items=(trace,))}, sequence=1)
    changed = previous.copy()
    opcode = 'invoke-virtual' if owner == ARRAYLIST else 'invoke-interface'
    list_call(I(0, opcode, [0], target=owner + '->clear()V'), {}, changed, previous, 'test', pytest.fail)
    assert changed.object(0).list_items == () and previous.object(0).list_items == (trace,)
    handled, value = list_call(I(0, opcode + '/range', [0, 1], target=owner + '->get(I)Ljava/lang/Object;'),
                              {}, previous.copy(), previous, 'test', pytest.fail)
    assert handled and value.uncertain


@pytest.mark.parametrize('opcode', ['invoke-static', 'invoke-virtual'])
@pytest.mark.parametrize('owner', [ARRAYLIST, LIST])
def test_list_through_local_call(opcode, owner):
    helper = 'Ltest/Helper;->read(' + owner + ')Ljava/lang/String;'
    entry = method(ENTRY, [I(0, 'new-instance', [4], defs=[4], literal=ARRAYLIST),
        I(2, 'invoke-direct', [4], target=ARRAYLIST + '-><init>()V'),
        I(4, 'invoke-virtual', [4, 1], target=ARRAYLIST + '->add(Ljava/lang/Object;)Z'),
        I(6, opcode, [4] if opcode == 'invoke-static' else [9, 4], target=helper),
        I(8, 'move-result-object', [8], defs=[8]), I(10, 'invoke-virtual', [9, 8], target=SINK),
        I(12, 'return-object', [8])], [0, 1, 2, 3])
    callee = method(helper, [I(0, 'const/4', [2], defs=[2], literal=0),
        I(2, 'invoke-virtual' if owner == ARRAYLIST else 'invoke-interface', [1, 2], target=owner + '->get(I)Ljava/lang/Object;'),
        I(4, 'move-result-object', [3], defs=[3]), I(6, 'return-object', [3])],
        [1] if opcode == 'invoke-static' else [0, 1])
    flows, _ = FlowEngine(RuleRegistry()).analyze(Program(methods={ENTRY: entry, helper: callee}), {ENTRY}, Cancellation())
    assert flows[0].verification == ('LIKELY' if opcode == 'invoke-static' else 'POTENTIAL')


@pytest.mark.parametrize('descriptor', [None, 'Ljava/util/LinkedList;', 'Ltest/CustomList;'])
def test_interface_requires_exact_allocation(descriptor):
    previous = Memory() if descriptor is None else Memory(
        refs={0: ('allocation', 1)}, objects={('allocation', 1): ObjectValue(descriptor, list_items=(Trace('source', (), True),))})
    previous.constants[1] = 0
    diagnostics = []
    handled, result = list_call(I(0, 'invoke-interface', [0, 1], target=LIST + '->get(I)Ljava/lang/Object;'),
                               {}, previous.copy(), previous, 'test', diagnostics.append)
    assert handled and result is None and diagnostics


@pytest.mark.parametrize('owner,member,opcode,registers', [
    (LIST, '<init>()V', 'invoke-direct', [0]),
    (COLLECTION, 'get(I)Ljava/lang/Object;', 'invoke-interface', [0, 1]),
    (LIST, 'get(I)Ljava/lang/Object;', 'invoke-virtual', [0, 1]),
    (LIST, 'get(I)Ljava/lang/Object;', 'invoke-interface', [0]),
    (LIST, 'get(I)Ljava/lang/Object;', 'invoke-interface-invalid', [0, 1]),
])
def test_invalid_interface_call_invalidates_slots(owner, member, opcode, registers):
    previous = Memory(refs={0: ('allocation', 1)}, constants={1: 0},
        objects={('allocation', 1): ObjectValue(ARRAYLIST, list_items=(Trace('source', (), True),))})
    changed, diagnostics = previous.copy(), []
    handled, result = list_call(I(0, opcode, registers, target=owner + '->' + member),
                               {}, changed, previous, 'test', diagnostics.append)
    assert handled and result is None and diagnostics
    assert changed.object(0).list_items is None
    assert previous.object(0).list_items is not None
