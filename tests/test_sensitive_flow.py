import pytest
from analyzer.analyzers.sensitive_flow import sensitive_flows
from analyzer.core.models import Instruction as I, Program, AnalysisResult
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.core.dataflow import FlowEngine
from analyzer.core.rules.registry import RuleRegistry
from conftest import method, SOURCE

TOKEN = 'Landroid/accounts/AccountManager;->peekAuthToken(Landroid/accounts/Account;Ljava/lang/String;)Ljava/lang/String;'
LOG = 'Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I'
PREF = 'Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;'
SQL = 'Landroid/database/sqlite/SQLiteStatement;->bindString(ILjava/lang/String;)V'
WRITE = 'Ljava/io/Writer;->write(Ljava/lang/String;)V'
CLIP = 'Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V'
NEWCLIP = 'Landroid/content/ClipData;->newPlainText(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;'


def analyze(code, source=TOKEN, **kwargs):
    m = method('Ltest/A;->run()V', [I(0, 'invoke-virtual', [8, 9, 10], target=source),
        I(6, 'move-result-object', [0], defs=[0]), *code])
    p = Program(methods={m.signature: m})
    return sensitive_flows(p, Cancellation(), **kwargs), p


@pytest.mark.parametrize('target,regs,opcode,rule', [
    (LOG, [2, 0], 'invoke-static', '001'),
    ('Landroid/util/Log;->println(ILjava/lang/String;Ljava/lang/String;)I', [3, 2, 0], 'invoke-static', '002'),
    (PREF, [3, 2, 0], 'invoke-interface', '003'),
    (SQL, [3, 2, 0], 'invoke-virtual', '004'),
    (WRITE, [3, 0], 'invoke-virtual', '005'),
    ('Landroid/content/ClipboardManager;->setText(Ljava/lang/CharSequence;)V', [3, 0], 'invoke-virtual', '006')])
def test_credential_value_argument(target, regs, opcode, rule):
    (findings, _, coverage), p = analyze([I(8, opcode, regs, target=target), I(14, 'return-void')])
    f, = findings
    assert f.rule_id == 'AOS-SENSITIVE-' + rule and f.type == 'REVIEW'
    assert f.verification == 'MANUAL_REVIEW' and f.analysis_level == 'L3' and not f.attack_path
    assert f.source == TOKEN and f.location.offset == 8 and f.data_flow
    assert coverage['rules_sha256'] and f.validation['persistence_or_exposure'] == 'UNKNOWN'
    assert not FlowEngine(RuleRegistry()).analyze(p, set(), Cancellation())[0]
    saved = AnalysisResult('test.apk', '0' * 64, findings=findings, program=p)
    assert AnalysisResult.from_dict(saved.to_dict()).findings[0].id == f.id


@pytest.mark.parametrize('target,regs,opcode', [(LOG, [0, 2], 'invoke-static'),
    (PREF, [3, 0, 2], 'invoke-interface'), (SQL, [3, 0, 2], 'invoke-virtual'),
    (WRITE, [0, 2], 'invoke-virtual')])
def test_non_value_argument_not_classified_as_value_flow(target, regs, opcode):
    (findings, _, _), _ = analyze([I(8, opcode, regs, target=target)])
    assert not findings


def test_external_input_is_not_automatically_secret():
    (findings, _, _), _ = analyze([I(8, 'invoke-static', [2, 0], target=LOG)], source=SOURCE)
    assert not findings


def test_overwrite_removes_secret_trace():
    (findings, _, _), _ = analyze([I(8, 'const-string', [0], defs=[0], literal='public'),
                                  I(10, 'invoke-static', [2, 0], target=LOG)])
    assert not findings


@pytest.mark.parametrize('payload,expected', [(True, 1), (False, 0)])
def test_clipboard_payload_transfer_not_label(payload, expected):
    (findings, _, _), _ = analyze([I(8, 'invoke-static', [2, 0] if payload else [0, 2], target=NEWCLIP),
        I(14, 'move-result-object', [4], defs=[4]), I(16, 'invoke-virtual', [3, 4], target=CLIP)])
    assert len(findings) == expected


def test_string_encoding_and_helper_return():
    helper = 'Ltest/A;->encode(Ljava/lang/String;)[B'
    m = method(helper, [I(0, 'invoke-virtual', [0], target='Ljava/lang/String;->getBytes()[B'),
        I(6, 'move-result-object', [1], defs=[1]), I(8, 'return-object', [1])], [0])
    (_, p) = analyze([I(8, 'invoke-static', [0], target=helper),
        I(14, 'move-result-object', [4], defs=[4]),
        I(16, 'invoke-virtual', [3, 4], target='Ljava/io/FileOutputStream;->write([B)V')])
    p.methods[helper] = m
    findings, _, _ = sensitive_flows(p, Cancellation())
    assert len(findings) == 1 and findings[0].analysis_level == 'L4'
    assert any('method return' in s['label'] for s in findings[0].data_flow)


def test_unknown_transform_is_not_assumed_safe_or_transparent():
    (findings, diagnostics, _), _ = analyze([I(8, 'invoke-static', [0], target='Lunknown/Cipher;->encode(Ljava/lang/String;)Ljava/lang/String;'),
        I(14, 'move-result-object', [4], defs=[4]), I(16, 'invoke-static', [2, 4], target=LOG)])
    assert not findings and any('Unmodeled external call' in d for d in diagnostics)


def test_budget_and_cancellation():
    (_, diagnostics, _), _ = analyze([I(8, 'invoke-static', [2, 0], target=LOG)], max_steps=1)
    assert any('budget' in d for d in diagnostics)
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        sensitive_flows(Program(methods={'x': method('x', [])}), token)


@pytest.mark.parametrize('source', [TOKEN,
    'Landroid/accounts/AccountManager;->getPassword(Landroid/accounts/Account;)Ljava/lang/String;',
    'Landroid/accounts/AccountManager;->blockingGetAuthToken(Landroid/accounts/Account;Ljava/lang/String;Z)Ljava/lang/String;'])
def test_all_declared_sources(source):
    (findings, _, _), _ = analyze([I(8, 'invoke-static', [2, 0], target=LOG)], source=source)
    assert len(findings) == 1 and findings[0].source == source


def test_exhausted_shared_budget_reports_incomplete():
    (findings, diagnostics, coverage), _ = analyze([I(8, 'invoke-static', [2, 0], target=LOG)], max_steps=0)
    assert not findings and coverage['steps'] == 0 and coverage['step_limit'] == 0
    assert any('budget exhausted' in d for d in diagnostics)


def test_no_credential_sources_does_not_explore_unrelated_boundaries():
    m = method('Ltest/A;->run()V', [I(0, 'invoke-virtual', [1], target='Ljava/lang/Thread;->start()V')])
    findings, diagnostics, coverage = sensitive_flows(Program(methods={m.signature: m}), Cancellation())
    assert not findings and not diagnostics and coverage['explored_roots'] == 0
