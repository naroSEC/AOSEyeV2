import pytest
from analyzer.core.models import Instruction as I, Program
from analyzer.core.dataflow import Trace, FlowEngine
from analyzer.core.objectflow import ObjectValue, Memory
from analyzer.core.arrayflow import length
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from conftest import method, SINK
from test_arrayflow import ENTRY


@pytest.mark.parametrize('kind', ['[Ljava/lang/String;', '[Ljava/lang/Object;'])
@pytest.mark.parametrize('count', [0, 1, 64])
@pytest.mark.parametrize('same_register', [False, True])
def test_length_is_constant_not_element_taint(kind, count, same_register):
    obj = ObjectValue(kind, array_length=count, array_elements={None: Trace('input', (), True)})
    source = 0 if same_register else 1
    previous = Memory(refs={source: 'array', 0: 'array'}, constants={0: 99}, objects={'array': obj})
    changed, regs, diagnostics = previous.copy(), {0: Trace('stale', (), True)}, []
    length(I(4, 'array-length', [0, source]), regs, changed, previous, 'test', diagnostics.append)
    assert not diagnostics and changed.constants[0] == count and 0 not in changed.refs and 0 not in regs
    assert previous.object(source) is obj and changed.objects['array'] is obj


@pytest.mark.parametrize('case', ['missing', 'type', 'unknown', 'negative', 'bool', 'budget', 'arity', 'empty'])
def test_unresolved_length_clears_stale_destination(case):
    count = {'unknown': None, 'negative': -1, 'bool': True, 'budget': 65}.get(case, 1)
    obj = ObjectValue('Ljava/lang/Object;' if case == 'type' else '[Ljava/lang/Object;', array_length=count)
    previous = Memory(refs={0: 'array'} if case == 'missing' else {0: 'array', 1: 'array'},
                      constants={0: 99}, objects={'array': obj})
    changed, regs, diagnostics = previous.copy(), {0: Trace('stale', (), True)}, []
    length(I(4, 'array-length', [] if case == 'empty' else [0] if case == 'arity' else [0, 1]),
           regs, changed, previous, 'test', diagnostics.append)
    assert diagnostics and previous.objects['array'] is obj
    if case != 'empty':
        assert 0 not in regs and 0 not in changed.constants and 0 not in changed.refs


@pytest.mark.parametrize('defs', [[], [6]])
@pytest.mark.parametrize('known', [False, True])
def test_length_drives_allocation_without_reusing_stale_constant(defs, known):
    code = [I(0, 'const/4', [3], defs=[3], literal=1),
            I(2, 'new-array', [4, 3], defs=[4], literal='[Ljava/lang/Object;'),
            I(4, 'const/4', [6], defs=[6], literal=1),
            I(6, 'array-length', [6, 4 if known else 12], defs=defs),
            I(8, 'new-array', [7, 6], defs=[7], literal='[Ljava/lang/Object;'),
            I(10, 'const/4', [5], defs=[5], literal=0),
            I(12, 'aput-object', [1, 7, 5]),
            I(14, 'aget-object', [8, 7, 5], defs=[8]),
            I(16, 'invoke-virtual', [9, 8], target=SINK), I(18, 'return-object', [8])]
    findings, diagnostics = FlowEngine(RuleRegistry()).analyze(
        Program(methods={ENTRY: method(ENTRY, code, [0, 1, 2, 10])}), {ENTRY}, Cancellation())
    assert bool(findings) == known
    assert bool(diagnostics) != known
