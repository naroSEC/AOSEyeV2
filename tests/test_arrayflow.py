import pytest
from analyzer.app.jobs import Cancellation
from analyzer.core.dataflow import FlowEngine
from analyzer.core.rules.registry import RuleRegistry
from analyzer.core.models import Instruction as I, Program
from conftest import method, SINK

ENTRY = 'Ltest/Provider;->call(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;'


def analyze(extra=(), length=2, read_index=0, unknown_write=False, array_register=4):
    code = [I(0, 'const/4', [3], defs=[3], literal=length),
            I(2, 'new-array', [4, 3], defs=[4], literal='[Ljava/lang/String;'),
            I(4, 'const/4', [5], defs=[5], literal=0)]
    code.append(I(6, 'aput-object', [1, 4, 12 if unknown_write else 5]))
    code.extend(extra)
    if read_index is not None:
        code.append(I(40, 'const/4', [6], defs=[6], literal=read_index))
    code.extend([I(42, 'aget-object', [8, array_register, 6], defs=[8]),
                 I(44, 'invoke-virtual', [9, 8], target=SINK), I(50, 'return-object', [8])])
    program = Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 10])})
    engine = FlowEngine(RuleRegistry())
    return engine.analyze(program, {ENTRY}, Cancellation())


def test_exact_array_flow():
    findings, diagnostics = analyze()
    assert not diagnostics and len(findings) == 1
    assert findings[0].verification == 'LIKELY'
    assert any('array read index 0' in row['label'] for row in findings[0].data_flow)


@pytest.mark.parametrize('index', [1, -1, 2])
def test_other_or_invalid_slot(index):
    assert not analyze(read_index=index)[0]


def test_strong_overwrite():
    assert not analyze([I(8, 'const-string', [7], defs=[7], literal='safe'),
                        I(10, 'aput-object', [7, 4, 5])])[0]


def test_alias_and_distinct_allocations():
    assert analyze([I(8, 'move-object', [11, 4], defs=[11])], array_register=11)[0]
    assert not analyze([I(8, 'new-array', [11, 3], defs=[11], literal='[Ljava/lang/String;')], array_register=11)[0]


@pytest.mark.parametrize('write', [False, True])
def test_unknown_index_is_potential(write):
    findings, diagnostics = analyze(unknown_write=write, read_index=0 if write else None)
    assert diagnostics and findings[0].verification == 'POTENTIAL'


@pytest.mark.parametrize('length', [0, -1, 65, None])
def test_allocation_budget_and_invalid_length(length):
    findings, diagnostics = analyze(length=length)
    assert not findings and diagnostics


@pytest.mark.parametrize('read_index', [0, 1, None])
def test_unknown_write_is_cleared_only_at_exact_safe_store(read_index):
    findings, _ = analyze([I(8, 'const-string', [7], defs=[7], literal='safe'),
                           I(10, 'aput-object', [7, 4, 5])], unknown_write=True, read_index=read_index)
    assert bool(findings) == (read_index != 0)
    if findings:
        assert findings[0].verification == 'POTENTIAL'


@pytest.mark.parametrize('opcode', ['invoke-static', 'invoke-virtual'])
def test_array_argument_and_return(opcode):
    helper = 'Ltest/Helper;->read([Ljava/lang/String;)Ljava/lang/String;'
    entry = method(ENTRY, [I(0, 'const/4', [3], defs=[3], literal=1),
        I(2, 'new-array', [4, 3], defs=[4], literal='[Ljava/lang/String;'),
        I(4, 'const/4', [5], defs=[5], literal=0), I(6, 'aput-object', [1, 4, 5]),
        I(8, opcode, [4] if opcode == 'invoke-static' else [9, 4], target=helper),
        I(10, 'move-result-object', [8], defs=[8]), I(12, 'invoke-virtual', [9, 8], target=SINK),
        I(14, 'return-object', [8])], [0, 1, 2, 10])
    callee = method(helper, [I(0, 'const/4', [2], defs=[2], literal=0),
        I(2, 'aget-object', [3, 1, 2], defs=[3]), I(4, 'return-object', [3])],
        [1] if opcode == 'invoke-static' else [0, 1])
    findings, _ = FlowEngine(RuleRegistry()).analyze(Program(methods={ENTRY: entry, helper: callee}), {ENTRY}, Cancellation())
    assert findings[0].verification == ('LIKELY' if opcode == 'invoke-static' else 'POTENTIAL')


@pytest.mark.parametrize('case', ['normal', 'range', 'other_slot', 'overwrite', 'stale_result', 'unsupported', 'budget'])
def test_filled_array(case):
    code = [I(0, 'const-string', [3], defs=[3], literal='safe'),
            I(2, 'filled-new-array/range' if case == 'range' else 'filled-new-array',
              [1] * 65 if case == 'budget' else [1, 3], literal='[I' if case == 'unsupported' else '[Ljava/lang/String;')]
    if case == 'stale_result':
        code.append(I(3, 'const/4', [6], defs=[6], literal=0))
    code.extend([I(4, 'move-result-object', [4], defs=[4]),
                 I(6, 'const/4', [5], defs=[5], literal=1 if case == 'other_slot' else 0)])
    if case == 'overwrite':
        code.append(I(8, 'aput-object', [3, 4, 5]))
    code.extend([I(10, 'aget-object', [8, 4, 5], defs=[8]),
                 I(12, 'invoke-virtual', [9, 8], target=SINK), I(14, 'return-object', [8])])
    program = Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 10])})
    findings, diagnostics = FlowEngine(RuleRegistry()).analyze(program, {ENTRY}, Cancellation())
    assert bool(findings) == (case in ('normal', 'range'))
    if findings:
        assert findings[0].verification == 'LIKELY'
        assert any('filled array index 0' in row['label'] for row in findings[0].data_flow)
    if case in ('unsupported', 'budget', 'stale_result'):
        assert diagnostics
