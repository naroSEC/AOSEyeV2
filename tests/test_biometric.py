import pytest
from analyzer.analyzers.biometric import biometric_context, FAMILIES
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.core.models import Instruction as I, Program, AnalysisResult
from conftest import method


def program(family=FAMILIES[0], error=False, change='positive'):
    owner = 'Ltest/Bio;'
    success = owner + '->onAuthenticationSucceeded(' + family + '$AuthenticationResult;)V'
    name = 'onAuthenticationError(ILjava/lang/CharSequence;)V' if error else 'onAuthenticationFailed()V'
    code = [I(0, 'move-object', [0, 5]), I(2, 'const/4', [1], literal=0),
            I(4, 'invoke-virtual', [0, 1], target=success), I(10, 'return-void')]
    if change == 'other_receiver': code[0].registers = [0, 9]
    elif change == 'non_null': code[1].literal = 1
    elif change == 'wrong_type': code[1].literal = False
    elif change == 'unknown_result': code[1] = I(2, 'move-object', [1, 9])
    elif change == 'static': code[2].opcode = 'invoke-static'
    elif change == 'branch': code[0].opcode = 'if-eqz'
    elif change == 'helper': code[2].target = 'Ltest/Helper;->allow()V'
    m = method(owner + '->' + name, code, [5, 6, 7] if error else [5])
    m.exception_status = 'UNKNOWN' if change == 'exceptions' else 'NONE'
    if change == 'truncated': m.diagnostics = ['truncated']
    target = method(success, [I(0, 'return-void')], [5, 6])
    p = Program(methods={m.signature: m, success: target},
                class_hierarchy={owner: family + '$AuthenticationCallback;'})
    if change == 'unrelated': p.class_hierarchy.clear()
    elif change == 'missing_success': p.methods.pop(success)
    return p


@pytest.mark.parametrize('family', FAMILIES)
@pytest.mark.parametrize('error', [True, False])
def test_direct_forward_is_review_not_bypass(family, error):
    p = program(family, error)
    f, = biometric_context(p, Cancellation())
    assert f.rule_id == 'AOS-AUTH-001' and f.type == 'REVIEW'
    assert not f.attack_path and f.verification == 'MANUAL_REVIEW'
    assert f.validation['privileged_action'] == 'UNKNOWN' and f.location.offset == 4
    result = AnalysisResult('test.apk', '0' * 64, findings=[f], program=p)
    assert AnalysisResult.from_dict(result.to_dict()).findings[0].id == f.id


@pytest.mark.parametrize('change', ['other_receiver', 'non_null', 'wrong_type', 'unknown_result',
    'static', 'branch', 'helper', 'exceptions', 'truncated', 'unrelated', 'missing_success'])
def test_unsupported_or_unproven_patterns(change):
    assert not biometric_context(program(change=change), Cancellation())


def test_cancel():
    cancel = Cancellation()
    cancel.cancel()
    with pytest.raises(Cancelled):
        biometric_context(program(), cancel)
