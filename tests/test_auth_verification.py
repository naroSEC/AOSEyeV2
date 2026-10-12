import pytest
from analyzer.analyzers.auth_verification import authentication_verification, VERIFY
from analyzer.core.models import Instruction as I, Program, AnalysisResult
from analyzer.app.jobs import Cancellation, Cancelled
from conftest import method


def fixture(change='positive'):
    code = [I(0, 'invoke-virtual', [8, 9], target=next(iter(VERIFY))),
            I(6, 'const/4', [0], literal=1), I(8, 'return', [0])]
    if change == 'used': code[1] = I(6, 'move-result', [0])
    if change == 'false': code[1].literal = 0
    if change == 'wrong_opcode': code[0].opcode = 'invoke-static'
    if change == 'wrong_count': code[0].registers = [8]
    if change == 'unknown': code[1] = I(6, 'iget', [0, 1])
    if change == 'unrelated_api': code[0].target = 'Lother;->verify([B)Z'
    m = method('Ltest/A;->verify()Z', code)
    m.exception_status = 'NONE' if change != 'exception' else 'UNKNOWN'
    if change == 'branch': code[0].successors = [6, 8]
    if change == 'truncated': m.diagnostics = ['truncated']
    return Program(methods={m.signature: m})


def test_discarded_signature_result_does_not_assert_bypass():
    p = fixture()
    f, = authentication_verification(p, Cancellation())
    assert f.rule_id == 'AOS-AUTH-002' and f.type == 'REVIEW' and not f.attack_path
    assert f.validation['authorization_role'] == 'UNKNOWN'
    assert AnalysisResult.from_dict(AnalysisResult('a.apk', '0'*64, program=p, findings=[f]).to_dict()).findings[0].id == f.id


@pytest.mark.parametrize('change', ['used', 'false', 'wrong_opcode', 'wrong_count', 'unknown',
                                  'unrelated_api', 'exception', 'branch', 'truncated'])
def test_no_unsupported_or_rejecting_path(change):
    assert not authentication_verification(fixture(change), Cancellation())


def test_cancel():
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled): authentication_verification(fixture(), token)
