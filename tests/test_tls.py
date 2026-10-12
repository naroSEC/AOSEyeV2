import pytest
from analyzer.analyzers.tls import tls_context, HOST, TRUST, SSL, PROCEED
from analyzer.core.models import Instruction as I, Program
from conftest import method


def program(name, code):
    m = method('Ltest/Tls;->' + name, code, [5, 6, 7, 8])
    m.exception_status = 'NONE'
    return Program(methods={m.signature: m}, class_hierarchy={'Ltest/Tls;': 'Landroid/webkit/WebViewClient;'})


def test_noop_trust_is_not_a_confirmed_vulnerability():
    p = program(TRUST, [I(0, 'return-void')])
    f, = tls_context(p)
    assert f.rule_id == 'AOS-TLS-001' and f.type == 'REVIEW'
    assert f.verification == 'MANUAL_REVIEW' and not f.attack_path
    assert 'Interface implementation is not verified' in f.description


@pytest.mark.parametrize('value,expected', [(1, True), (0, False), (-1, False), (True, False), ('1', False)])
def test_hostname_constant_and_move(value, expected):
    p = program(HOST, [I(0, 'const/4', [0], literal=value), I(2, 'move', [1, 0]), I(4, 'return', [1])])
    assert bool(tls_context(p)) == expected


@pytest.mark.parametrize('opcode', ['invoke-virtual', 'invoke-virtual/range'])
def test_ssl_handler_parameter_alias(opcode):
    p = program(SSL, [I(0, 'move-object', [0, 7]), I(2, opcode, [0], target=PROCEED), I(8, 'return-void')])
    f, = tls_context(p)
    assert f.rule_id == 'AOS-TLS-003' and f.type == 'WEAKNESS' and f.analysis_level == 'L2'
    assert f.location.offset == 2
    assert f.standards == {'CWE': ['CWE-295']} and f.bytecode and f.evidence


@pytest.mark.parametrize('change', ['wrong_receiver', 'reassigned', 'cancel', 'unknown_parent', 'cycle',
    'unknown_exceptions', 'exception_region', 'diagnostic', 'branch', 'disconnected', 'early_return', 'wrong_signature'])
def test_ssl_negative_and_incomplete_metadata(change):
    p = program(SSL, [I(0, 'move-object', [0, 7]), I(2, 'invoke-virtual', [0], target=PROCEED), I(8, 'return-void')])
    m = next(iter(p.methods.values()))
    if change == 'wrong_receiver': m.instructions[1].registers = [6]
    elif change == 'reassigned': m.instructions[0].registers = [0, 6]
    elif change == 'cancel': m.instructions[1].target = PROCEED.replace('proceed', 'cancel')
    elif change == 'unknown_parent': p.class_hierarchy.clear()
    elif change == 'cycle': p.class_hierarchy['Ltest/Tls;'] = 'Ltest/Tls;'
    elif change == 'unknown_exceptions': m.exception_status = 'UNKNOWN'
    elif change == 'exception_region': m.exception_regions = [{'start': 0}]
    elif change == 'diagnostic': m.diagnostics = ['truncated body']
    elif change == 'branch': m.instructions[0].opcode = 'if-eqz'
    elif change == 'disconnected': m.instructions[0].successors = []
    elif change == 'early_return': m.instructions[0].opcode = 'return-void'
    elif change == 'wrong_signature': m.signature = m.signature.replace('onReceivedSslError', 'notACallback')
    assert not tls_context(p)


def test_hostname_unknown_move_kills_constant():
    p = program(HOST, [I(0, 'const/4', [0], literal=1), I(2, 'move', [0, 4]), I(4, 'return', [0])])
    assert not tls_context(p)


def test_trust_delegate_is_not_noop():
    p = program(TRUST, [I(0, 'invoke-interface', [0, 1, 2], target='LDelegate;->' + TRUST), I(6, 'return-void')])
    assert not tls_context(p)


def test_cancellation():
    from analyzer.app.jobs import Cancellation, Cancelled
    cancel = Cancellation()
    cancel.cancel()
    with pytest.raises(Cancelled):
        tls_context(program(TRUST, [I(0, 'return-void')]), cancel)


@pytest.mark.parametrize('ancestry', ['direct', 'parent', 'interface', 'cycle', 'missing'])
@pytest.mark.parametrize('name,interface', [(TRUST, 'Ljavax/net/ssl/X509TrustManager;'),
                                         (HOST, 'Ljavax/net/ssl/HostnameVerifier;')])
def test_declared_interface_ancestry(name, interface, ancestry):
    code = [I(0, 'return-void')] if name == TRUST else [I(0, 'const/4', [0], literal=1), I(2, 'return', [0])]
    p = program(name, code)
    if ancestry == 'direct':
        p.class_interfaces['Ltest/Tls;'] = [interface]
    elif ancestry == 'parent':
        p.class_hierarchy['Ltest/Tls;'] = 'Lbase;'
        p.class_interfaces['Lbase;'] = [interface]
    elif ancestry == 'interface':
        p.class_interfaces = {'Ltest/Tls;': ['Lcustom;'], 'Lcustom;': [interface]}
    elif ancestry == 'cycle':
        p.class_interfaces = {'Ltest/Tls;': ['Lcustom;'], 'Lcustom;': ['Ltest/Tls;']}
    f, = tls_context(p)
    verified = ancestry in ('direct', 'parent', 'interface')
    assert f.type == ('WEAKNESS' if verified else 'REVIEW')
    assert f.severity == ('MEDIUM' if verified else 'INFO')
    assert f.verification == 'MANUAL_REVIEW' and not f.attack_path
    if verified:
        assert 'callback installation is not verified' in f.description


def test_interface_model_legacy_and_validation():
    from dataclasses import asdict
    from analyzer.core.input_validation import validate
    p = Program(class_interfaces={'Ltest;': ['Linterface;']})
    assert Program.from_dict(asdict(p)).class_interfaces == p.class_interfaces
    assert Program.from_dict({}).class_interfaces == {}
    with pytest.raises(ValueError):
        validate({'class_interfaces': {'Ltest;': 'not-an-array'}}, Program)
