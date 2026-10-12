import pytest
from analyzer.analyzers.crypto_parameters import PARAMETERS
from analyzer.analyzers.context import constant_context
from analyzer.core.models import Instruction as I, Program
from conftest import method


def run(target, value, opcode='invoke-direct', extra=(), cfg=None, registers=None):
    count, argument, _ = PARAMETERS[target]
    m = method('Ltest/C;->run()V', [I(0, 'const/16', [argument], defs=[argument], literal=value),
        *extra, I(10, opcode, list(range(count)) if registers is None else registers, target=target),
        I(16, 'return-void')])
    m.cfg = cfg or []
    return constant_context(Program(methods={m.signature: m}))


@pytest.mark.parametrize('target', PARAMETERS)
@pytest.mark.parametrize('opcode', ['invoke-direct', 'invoke-direct/range'])
def test_exact_argument_and_overloads(target, opcode):
    kind = PARAMETERS[target][2]
    findings = run(target, 1 if kind == 'iterations' else 64, opcode)
    f, = findings
    assert f.type == 'REVIEW' and f.verification == 'MANUAL_REVIEW' and not f.attack_path
    assert f.location.offset == 10 and f.analysis_level == 'L2'
    assert f.validation['runtime_use'] == 'UNKNOWN'


@pytest.mark.parametrize('target', PARAMETERS)
@pytest.mark.parametrize('value', [None, True, '1', -1, 0, 96, 128, 600000])
def test_other_or_unknown_values_not_classified_by_this_rule(target, value):
    assert not run(target, value)


@pytest.mark.parametrize('target', PARAMETERS)
def test_wrong_invoke_or_arity(target):
    value = 1 if PARAMETERS[target][2] == 'iterations' else 32
    assert not run(target, value, 'invoke-static')
    assert not run(target, value, registers=[])


@pytest.mark.parametrize('target', PARAMETERS)
def test_unknown_overwrite_and_block_boundary(target):
    arg = PARAMETERS[target][1]
    value = 1 if PARAMETERS[target][2] == 'iterations' else 32
    assert not run(target, value, extra=[I(2, 'move', [arg, 20])])
    assert not run(target, value, extra=[I(2, 'move-result', [arg])])
    assert not run(target, value, cfg=[{'offsets': [0]}, {'offsets': [10, 16]}])
    assert not run(target, value, extra=[I(2, 'if-eqz', [9])])
