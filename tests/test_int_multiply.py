import pytest
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import Trace, FlowEngine
from analyzer.core.objectflow import Memory
from analyzer.core.intflow import register_arithmetic, literal_arithmetic
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from conftest import method, SINK
from test_arrayflow import ENTRY

OPS = ['mul-int', 'mul-int/2addr', 'mul-int/lit8', 'mul-int/lit16']


def run(opcode, left, right, old=None):
    literal = '/lit' in opcode
    rr = [0, 1] if literal else [0, 2] if opcode.endswith('/2addr') else [0, 1, 2]
    src = 0 if opcode.endswith('/2addr') else 1
    previous = Memory(refs={0: 'stale'}, constants={0: 99, src: left, 2: right})
    changed, regs, diagnostics = previous.copy(), {0: Trace('stale', (), True)}, []
    function = literal_arithmetic if literal else register_arithmetic
    function(I(0, opcode, rr, literal=right if literal else None), old or {}, regs, changed, previous, 'test', diagnostics.append)
    assert previous.constants[src] == left and 0 not in changed.refs
    return changed, regs, diagnostics


@pytest.mark.parametrize('opcode', OPS)
@pytest.mark.parametrize('left,right,expected', [(3, 2, 6), (-3, 2, -6), (-3, -2, 6), (7, 0, 0),
    (2147483647, 2, -2), (-2147483648, -1, -2147483648), (16777216, -128, -2147483648)])
def test_multiplication_wraps_int32(opcode, left, right, expected):
    changed, regs, diagnostics = run(opcode, left, right)
    assert not diagnostics and changed.constants[0] == expected and 0 not in regs


@pytest.mark.parametrize('opcode', OPS)
@pytest.mark.parametrize('value', [None, True, '1', 1.5, 2147483648])
def test_unknown_operand_preserves_uncertain_input(opcode, value):
    src = 0 if opcode.endswith('/2addr') else 1
    changed, regs, diagnostics = run(opcode, value, 0, {src: Trace('input', (), True)})
    assert diagnostics and 0 not in changed.constants and regs[0].uncertain


@pytest.mark.parametrize('opcode,literal', [('mul-int/lit8', 128), ('mul-int/lit8', -129),
    ('mul-int/lit16', 32768), ('mul-int/lit16', -32769)])
def test_invalid_multiply_literal(opcode, literal):
    changed, regs, diagnostics = run(opcode, 1, literal)
    assert diagnostics and 0 not in changed.constants and 0 not in regs


@pytest.mark.parametrize('opcode', OPS)
@pytest.mark.parametrize('defs', [[], [6]])
def test_multiply_controls_array_allocation(opcode, defs):
    literal = '/lit' in opcode
    rr = [6, 6] if literal else [6, 5] if opcode.endswith('/2addr') else [6, 6, 5]
    code = [I(0, 'const/4', [6], defs=[6], literal=2), I(2, 'const/4', [5], defs=[5], literal=3),
        I(4, opcode, rr, defs=defs, literal=3 if literal else None),
        I(6, 'new-array', [4, 6], defs=[4], literal='[Ljava/lang/Object;'),
        I(8, 'const/4', [5], defs=[5], literal=5), I(10, 'aput-object', [1, 4, 5]),
        I(12, 'aget-object', [8, 4, 5], defs=[8]), I(14, 'invoke-virtual', [9, 8], target=SINK),
        I(16, 'return-object', [8])]
    findings, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 10])}), {ENTRY}, Cancellation())
    assert not diagnostics and len(findings) == 1 and findings[0].verification == 'LIKELY'
