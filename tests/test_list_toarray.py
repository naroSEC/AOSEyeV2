import pytest
from analyzer.app.jobs import Cancellation
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import FlowEngine, Trace
from analyzer.core.rules.registry import RuleRegistry
from analyzer.core.objectflow import ARRAYLIST, Memory, ObjectValue
from analyzer.core.listflow import LIST, COLLECTION, list_call
from conftest import method, SINK
from test_arrayflow import ENTRY


@pytest.mark.parametrize('owner', [ARRAYLIST, LIST, COLLECTION])
@pytest.mark.parametrize('ranged', [False, True])
@pytest.mark.parametrize('case', ['normal', 'list_overwrite', 'array_overwrite', 'list_survives', 'safe_slot'])
def test_toarray_pipeline(owner, ranged, case):
    code = []
    def emit(opcode, registers, **kw):
        code.append(I(len(code) * 2, opcode, registers, **kw))
    emit('new-instance', [4], defs=[4], literal=ARRAYLIST)
    emit('invoke-direct', [4], target=ARRAYLIST + '-><init>()V')
    emit('invoke-virtual', [4, 1], target=ARRAYLIST + '->add(Ljava/lang/Object;)Z')
    emit('const-string', [6], defs=[6], literal='safe')
    emit('invoke-virtual', [4, 6], target=ARRAYLIST + '->add(Ljava/lang/Object;)Z')
    op = 'invoke-virtual' if owner == ARRAYLIST else 'invoke-interface'
    emit(op + ('/range' if ranged else ''), [4], target=owner + '->toArray()[Ljava/lang/Object;')
    emit('move-result-object', [7], defs=[7])
    emit('const/4', [5], defs=[5], literal=1 if case == 'safe_slot' else 0)
    if case == 'list_overwrite':
        emit('invoke-virtual', [4, 5, 6], target=ARRAYLIST + '->set(ILjava/lang/Object;)Ljava/lang/Object;')
    if case in ('array_overwrite', 'list_survives'):
        emit('aput-object', [6, 7, 5])
    if case == 'list_survives':
        emit('invoke-virtual', [4, 5], target=ARRAYLIST + '->get(I)Ljava/lang/Object;')
        emit('move-result-object', [8], defs=[8])
    else:
        emit('aget-object', [8, 7, 5], defs=[8])
    emit('invoke-virtual', [9, 8], target=SINK)
    emit('return-object', [8])
    flows, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 3])}), {ENTRY}, Cancellation())
    assert bool(flows) == (case in ('normal', 'list_overwrite', 'list_survives'))
    if flows:
        assert flows[0].verification == 'LIKELY'


@pytest.mark.parametrize('case', ['empty', 'uncertain', 'unknown', 'object_budget', 'length_budget', 'overload'])
def test_toarray_identity_limits_and_uncertainty(case, monkeypatch):
    trace = Trace('source', (), True, True)
    items = () if case == 'empty' else None if case == 'unknown' else (trace, None)
    previous = Memory(refs={0: ('allocation', 1)}, objects={('allocation', 1): ObjectValue(ARRAYLIST, list_items=items)}, sequence=1)
    changed, diagnostics = previous.copy(), []
    if case == 'object_budget':
        monkeypatch.setattr('analyzer.core.arrayflow.MAX_ARRAY_OBJECTS', 0)
    if case == 'length_budget':
        monkeypatch.setattr('analyzer.core.arrayflow.MAX_ARRAY_LENGTH', 1)
    member = 'toArray([Ljava/lang/Object;)[Ljava/lang/Object;' if case == 'overload' else 'toArray()[Ljava/lang/Object;'
    handled, result = list_call(I(0, 'invoke-interface', [0, 2] if case == 'overload' else [0], target=LIST + '->' + member),
                               {}, changed, previous, 'test', diagnostics.append)
    assert handled and result is None
    if case in ('empty', 'uncertain'):
        assert not diagnostics and changed.result_ref != previous.refs[0]
        array = changed.objects[changed.result_ref]
        assert array.type == '[Ljava/lang/Object;' and array.array_length == len(items)
        if case == 'uncertain':
            assert array.array_elements[0].uncertain and array.array_elements[1] is None
    else:
        assert diagnostics and changed.result_ref is None
    if case != 'overload':
        assert changed.object(0) == previous.object(0)
    assert previous.object(0).list_items == items
