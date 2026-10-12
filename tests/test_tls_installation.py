import pytest
from analyzer.analyzers.tls_installation import tls_installation, SETTERS
from analyzer.analyzers.tls import tls_context, HOST
from analyzer.core.models import Program, Instruction as I, AnalysisResult
from analyzer.app.jobs import Cancellation, Cancelled
from conftest import method

OWNER = 'Ltest/Host;'
SET = next(iter(SETTERS))


def setup(change='positive'):
    callback = method(OWNER + '->' + HOST, [I(0, 'const/4', [0], literal=1), I(2, 'return', [0])])
    callback.exception_status = 'NONE'
    code = [I(0, 'new-instance', [0], defs=[0], literal=OWNER),
            I(2, 'invoke-direct', [0], target=OWNER + '-><init>()V'),
            I(8, 'move-object', [1, 0], defs=[1]), I(10, 'invoke-virtual', [5, 1], target=SET),
            I(16, 'return-void')]
    if change == 'overwrite': code[2] = I(8, 'const/4', [1], literal=0)
    elif change == 'wide_overwrite': code.insert(3, I(9, 'const-wide/16', [0], literal=0))
    elif change == 'escape': code[2] = I(8, 'invoke-static', [0], target='Lhelper;->escape(Ljava/lang/Object;)V')
    elif change == 'wrong_argument': code[3].registers = [1, 5]
    elif change == 'wrong_opcode': code[3].opcode = 'invoke-static'
    elif change == 'wrong_constructor': code[1].target = 'Lother;-><init>()V'
    elif change == 'uninitialized': code[1] = I(2, 'nop')
    elif change == 'branch': code[2] = I(8, 'if-eqz', [0])
    elif change == 'safe_callback': callback.instructions[0].literal = 0
    install = method('Ltest/Install;->run()V', code)
    install.exception_status = 'NONE'
    if change == 'exception_unknown': install.exception_status = 'UNKNOWN'
    elif change == 'truncated': install.diagnostics = ['truncated']
    p = Program(methods={callback.signature: callback, install.signature: install},
                class_interfaces={OWNER: ['Ljavax/net/ssl/HostnameVerifier;']})
    if change == 'interface_unknown': p.class_interfaces.clear()
    return p


def test_callback_object_setter_connection():
    p = setup()
    findings = tls_installation(p, tls_context(p), Cancellation())
    f, = findings
    assert f.rule_id == 'AOS-TLS-004' and f.type == 'WEAKNESS'
    assert f.verification == 'MANUAL_REVIEW' and not f.attack_path
    assert f.location.offset == 10 and f.data_flow[0]['offset'] == 0
    assert f.source == OWNER + '->' + HOST and f.validation['runtime_registration'] == 'UNKNOWN'
    result = AnalysisResult('test.apk', '0' * 64, findings=findings, program=p)
    assert AnalysisResult.from_dict(result.to_dict()).findings[0].id == f.id


@pytest.mark.parametrize('change', ['overwrite', 'wide_overwrite', 'escape', 'wrong_argument', 'wrong_opcode',
    'wrong_constructor', 'uninitialized', 'branch', 'safe_callback', 'exception_unknown', 'truncated', 'interface_unknown'])
def test_unproven_connections_not_promoted(change):
    p = setup(change)
    assert not tls_installation(p, tls_context(p), Cancellation())


def test_cancel():
    p = setup()
    cancel = Cancellation()
    cancel.cancel()
    with pytest.raises(Cancelled):
        tls_installation(p, tls_context(p), cancel)
