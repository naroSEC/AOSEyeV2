import pytest
from analyzer.analyzers.trust_array import trust_array_context, INIT, ARRAY
from analyzer.analyzers.tls import tls_context, TRUST
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.core.models import Program, Instruction as I, AnalysisResult
from conftest import method

OWNER = 'Ltest/Trust;'


def program(change='positive', filled=False):
    callback = method(OWNER + '->' + TRUST, [I(0, 'return-void')])
    callback.exception_status = 'NONE'
    code = [I(0, 'new-instance', [0], literal=OWNER), I(2, 'invoke-direct', [0], target=OWNER + '-><init>()V')]
    if filled:
        code += [I(8, 'filled-new-array', [0], literal=ARRAY), I(10, 'move-result-object', [2])]
    else:
        code += [I(8, 'const/4', [1], literal=1), I(10, 'new-array', [2, 1], literal=ARRAY),
                 I(12, 'const/4', [3], literal=0), I(14, 'aput-object', [0, 2, 3])]
    code += [I(20, 'invoke-virtual', [8, 9, 2, 9], target=INIT), I(26, 'return-void')]
    if change == 'wrong_argument': code[-2].registers = [8, 2, 9, 9]
    elif change == 'wrong_opcode': code[-2].opcode = 'invoke-static'
    elif change == 'uninitialized': code[1] = I(2, 'nop')
    elif change == 'wrong_constructor': code[1].target = 'Lother;-><init>()V'
    elif change == 'escape': code.insert(-2, I(18, 'invoke-static', [2], target='Lhelper;->modify([Ljava/lang/Object;)V'))
    elif change == 'overwrite': code.insert(-2, I(18, 'const/4', [2], literal=0))
    elif change == 'null_slot':
        code.insert(-2, I(18, 'aput-object', [3, 2, 3]))
    elif change == 'wrong_index': code[4].literal = 1
    elif change == 'multiple': code[2].literal = 2
    elif change == 'wrong_array_type': code[3].literal = '[Ljava/lang/Object;'
    elif change == 'alias':
        code.insert(-2, I(18, 'move-object', [4, 2]))
        code[-2].registers[2] = 4
    install = method('Ltest/Install;->run()V', code)
    install.exception_status = 'NONE'
    p = Program(methods={callback.signature: callback, install.signature: install},
                class_interfaces={OWNER: ['Ljavax/net/ssl/X509TrustManager;']})
    if change == 'unknown_interface': p.class_interfaces.clear()
    elif change == 'unknown_exception': install.exception_status = 'UNKNOWN'
    elif change == 'truncated': install.diagnostics = ['truncated']
    return p


@pytest.mark.parametrize('filled', [True, False])
def test_trust_array_connection_and_roundtrip(filled):
    p = program(filled=filled)
    f, = trust_array_context(p, tls_context(p), Cancellation())
    assert f.rule_id == 'AOS-TLS-006' and f.analysis_level == 'L3' and not f.attack_path
    assert f.verification == 'MANUAL_REVIEW' and f.validation['socket_use'] == 'UNKNOWN'
    result = AnalysisResult('test.apk', '0' * 64, findings=[f], program=p)
    assert AnalysisResult.from_dict(result.to_dict()).findings[0].id == f.id


@pytest.mark.parametrize('change', ['wrong_argument', 'wrong_opcode', 'uninitialized', 'wrong_constructor',
    'escape', 'overwrite', 'null_slot', 'wrong_index', 'wrong_array_type', 'unknown_interface',
    'unknown_exception', 'truncated'])
def test_unknown_or_ineligible_arrays(change):
    p = program(change)
    assert not trust_array_context(p, tls_context(p), Cancellation())


def test_array_alias():
    p = program('alias')
    assert len(trust_array_context(p, tls_context(p), Cancellation())) == 1


@pytest.mark.parametrize('filled', [False, True])
def test_multiple_array_candidate_not_provider_selection(filled):
    p = program('multiple')
    install = p.methods['Ltest/Install;->run()V']
    if filled:
        install.instructions[2:6] = [I(8, 'filled-new-array', [0, 0], literal=ARRAY, successors=[10]),
            I(10, 'move-result-object', [2], successors=[20])]
        install.instructions[1].successors = [8]
    rows = trust_array_context(p, tls_context(p), Cancellation())
    assert rows and all(f.rule_id == 'AOS-TLS-007' and f.type == 'REVIEW' for f in rows)
    assert all(f.validation['provider_selection'] == 'UNKNOWN' and f.validation['array_length'] == '2' for f in rows)


@pytest.mark.parametrize('size', [0, -1, 17])
def test_array_budget(size):
    p = program('multiple')
    p.methods['Ltest/Install;->run()V'].instructions[2].literal = size
    assert not trust_array_context(p, tls_context(p), Cancellation())


def test_cancel():
    p = program()
    cancel = Cancellation()
    cancel.cancel()
    with pytest.raises(Cancelled):
        trust_array_context(p, tls_context(p), cancel)
