import pytest
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import Trace, FlowEngine
from analyzer.core.objectflow import Memory
from analyzer.core.intflow import register_arithmetic as add_sub_registers
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from conftest import method, SINK
from test_arrayflow import ENTRY

OPS = ['add-int', 'sub-int', 'add-int/2addr', 'sub-int/2addr']


@pytest.mark.parametrize('opcode', OPS)
@pytest.mark.parametrize('left,right,add,sub', [(2, 1, 3, 1), (0, 0, 0, 0), (-2, 3, 1, -5),
    (2147483647, 1, -2147483648, 2147483646), (-2147483648, 1, -2147483647, 2147483647),
    (-2147483648, -1, 2147483647, -2147483647)])
def test_register_arithmetic_wrap_and_cleanup(opcode, left, right, add, sub):
    rr = [0, 2] if opcode.endswith('/2addr') else [0, 1, 2]
    src = rr[0] if len(rr) == 2 else rr[1]
    previous = Memory(refs={0: 'stale'}, constants={0: 99, src: left, 2: right})
    changed, regs, diagnostics = previous.copy(), {0: Trace('stale', (), True)}, []
    add_sub_registers(I(4, opcode, rr), {}, regs, changed, previous, 'test', diagnostics.append)
    assert not diagnostics and changed.constants[0] == (add if opcode.startswith('add-') else sub)
    assert 0 not in changed.refs and 0 not in regs and previous.constants[src] == left


@pytest.mark.parametrize('opcode', OPS)
@pytest.mark.parametrize('value', [None, True, '1', 1.5, 2147483648])
def test_unknown_operand_never_reuses_stale_constant(opcode, value):
    rr = [0, 2] if opcode.endswith('/2addr') else [0, 1, 2]
    src = rr[0] if len(rr) == 2 else rr[1]
    previous = Memory(constants={0: 99, src: value, 2: 1})
    changed, regs, diagnostics = previous.copy(), {}, []
    add_sub_registers(I(4, opcode, rr), {src: Trace('local', (), False), 2: Trace('input', (), True)},
                      regs, changed, previous, 'test', diagnostics.append)
    assert diagnostics and 0 not in changed.constants and regs[0].source == 'input' and regs[0].uncertain


@pytest.mark.parametrize('opcode', OPS)
def test_malformed_register_arithmetic_cleans_destination(opcode):
    previous = Memory(constants={0: 99})
    changed, regs, diagnostics = previous.copy(), {0: Trace('old', (), True)}, []
    add_sub_registers(I(4, opcode, [0]), {}, regs, changed, previous, 'test', diagnostics.append)
    assert diagnostics and 0 not in regs and 0 not in changed.constants


@pytest.mark.parametrize('opcode', OPS)
@pytest.mark.parametrize('defs', [[], [6]])
def test_register_arithmetic_selects_last_array_slot(opcode, defs):
    initial = 0 if opcode.startswith('add-') else 2
    rr = [6, 5] if opcode.endswith('/2addr') else [6, 6, 5]
    code = [I(0, 'const-string', [3], defs=[3], literal='safe'),
        I(2, 'filled-new-array', [3, 1], literal='[Ljava/lang/Object;'),
        I(4, 'move-result-object', [4], defs=[4]), I(6, 'const/4', [6], defs=[6], literal=initial),
        I(8, 'const/4', [5], defs=[5], literal=1), I(10, opcode, rr, defs=defs),
        I(12, 'aget-object', [8, 4, 6], defs=[8]), I(14, 'invoke-virtual', [9, 8], target=SINK),
        I(16, 'return-object', [8])]
    findings, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 10])}), {ENTRY}, Cancellation())
    assert not diagnostics and len(findings) == 1 and findings[0].verification == 'LIKELY'
    assert any(s['label'] == 'array read index 1' for s in findings[0].data_flow)
