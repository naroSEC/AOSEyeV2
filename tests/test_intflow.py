import pytest
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import Trace, FlowEngine
from analyzer.core.objectflow import Memory
from analyzer.core.intflow import literal_arithmetic as add_literal
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from conftest import method, SINK
from test_arrayflow import ENTRY


@pytest.mark.parametrize('opcode', ['add-int/lit8', 'add-int/lit16'])
@pytest.mark.parametrize('source,literal,expected', [(2, -1, 1), (0, 0, 0), (-1, 1, 0),
    (2147483647, 1, -2147483648), (-2147483648, -1, 2147483647), (1, -128, -127), (1, 127, 128)])
@pytest.mark.parametrize('same', [False, True])
def test_add_literal_int32_and_destination_cleanup(opcode, source, literal, expected, same):
    src = 0 if same else 1
    previous = Memory(refs={0: 'stale'}, constants={0: 99, src: source})
    changed, regs, diagnostics = previous.copy(), {0: Trace('stale', (), True)}, []
    add_literal(I(4, opcode, [0, src], literal=literal), {}, regs, changed, previous, 'test', diagnostics.append)
    assert not diagnostics and changed.constants[0] == expected and 0 not in changed.refs and 0 not in regs
    assert previous.constants[src] == source


@pytest.mark.parametrize('opcode,literal', [('add-int/lit8', -129), ('add-int/lit8', 128),
    ('add-int/lit16', -32769), ('add-int/lit16', 32768), ('add-int/lit8', True), ('add-int/lit16', None)])
def test_invalid_literal_clears_stale_value(opcode, literal):
    previous = Memory(constants={0: 99, 1: 1})
    changed, regs, diagnostics = previous.copy(), {0: Trace('stale', (), True)}, []
    add_literal(I(0, opcode, [0, 1], literal=literal), {}, regs, changed, previous, 'test', diagnostics.append)
    assert diagnostics and 0 not in changed.constants and 0 not in regs


@pytest.mark.parametrize('value', [None, True, '1', 1.5, 2147483648])
def test_unknown_source_keeps_trace_uncertain_without_guessing_constant(value):
    previous = Memory(constants={0: 99, 1: value})
    changed, regs, diagnostics = previous.copy(), {}, []
    add_literal(I(0, 'add-int/lit8', [0, 1], literal=-1), {1: Trace('input', (), True)},
                regs, changed, previous, 'test', diagnostics.append)
    assert diagnostics and 0 not in changed.constants and regs[0].uncertain and regs[0].source == 'input'


@pytest.mark.parametrize('literal', [-32768, 32767])
def test_lit16_extremes(literal):
    previous = Memory(constants={1: 0})
    changed, diagnostics = previous.copy(), []
    add_literal(I(0, 'add-int/lit16', [0, 1], literal=literal), {}, {}, changed, previous, 'test', diagnostics.append)
    assert not diagnostics and changed.constants[0] == literal


@pytest.mark.parametrize('defs', [[], [6]])
def test_array_length_minus_one_selects_last_slot(defs):
    code = [I(0, 'const-string', [3], defs=[3], literal='safe'),
        I(2, 'filled-new-array', [3, 1], literal='[Ljava/lang/Object;'),
        I(4, 'move-result-object', [4], defs=[4]), I(6, 'array-length', [6, 4], defs=[6]),
        I(8, 'add-int/lit8', [6, 6], defs=defs, literal=-1),
        I(10, 'aget-object', [8, 4, 6], defs=[8]), I(12, 'invoke-virtual', [9, 8], target=SINK),
        I(14, 'return-object', [8])]
    findings, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 10])}), {ENTRY}, Cancellation())
    assert not diagnostics and len(findings) == 1 and findings[0].verification == 'LIKELY'
    assert any(s['label'] == 'array read index 1' for s in findings[0].data_flow)
