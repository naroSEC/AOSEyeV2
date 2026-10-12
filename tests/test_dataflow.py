from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.core.dataflow import FlowEngine
from analyzer.core.rules.registry import RuleRegistry
from analyzer.core.models import Instruction, Program
from conftest import ENTRY, HELPER, SOURCE, SINK, method
import pytest


def run(program, entries=None, **kwargs):
    return FlowEngine(RuleRegistry(), **kwargs).analyze(program, entries or set(), Cancellation())


def test_interprocedural_external_path(flow_program):
    findings, _ = run(flow_program, {ENTRY})
    assert len(findings) == 1
    f = findings[0]
    assert (f.analysis_level, f.verification, f.confidence) == ('L5', 'LIKELY', 'HIGH')
    assert f.attack_path[0]['method'] == ENTRY
    assert f.location.method == HELPER and f.location.offset == 0
    assert f.validation['host_allowlist'] == 'UNKNOWN'


def test_source_without_external_entry_is_not_l5(flow_program):
    findings, _ = run(flow_program)
    assert findings[0].analysis_level == 'L4'
    assert findings[0].verification == 'POTENTIAL'


def test_register_overwrite_prevents_flow(flow_program):
    m = flow_program.methods[ENTRY]
    m.instructions[4] = Instruction(18, 'const-string', [2], defs=[2], literal='https://safe.example', successors=[20])
    assert not run(flow_program, {ENTRY})[0]


def test_wrong_sink_argument_does_not_taint_url(flow_program):
    flow_program.methods[HELPER].instructions[0].registers = [0, 1]
    assert not run(flow_program, {ENTRY})[0]


def test_unreachable_sink_not_scanned_as_flow(flow_program):
    flow_program.methods[ENTRY].instructions[4].successors = [26]
    assert not run(flow_program, {ENTRY})[0]


def test_virtual_dispatch_downgrades_confidence(flow_program):
    flow_program.methods[ENTRY].instructions[5].opcode = 'invoke-virtual'
    f = run(flow_program, {ENTRY})[0][0]
    assert f.confidence == 'MEDIUM' and f.verification == 'POTENTIAL'


def test_return_propagation(flow_program):
    ret = 'Ltest/Identity;->value(Ljava/lang/String;)Ljava/lang/String;'
    flow_program.methods[ret] = method(ret, [Instruction(0, 'return-object', [0])], [0])
    helper = method(HELPER, [Instruction(0, 'invoke-static', [0], target=ret),
        Instruction(6, 'move-result-object', [2], defs=[2]),
        Instruction(8, 'invoke-virtual', [1, 2], target=SINK), Instruction(14, 'return-void')], [0])
    flow_program.methods[HELPER] = helper
    assert run(flow_program, {ENTRY})[0][0].analysis_level == 'L5'


def test_field_flow_is_disclosed(flow_program):
    field = 'Ltest/Nav;->url:Ljava/lang/String;'
    flow_program.methods[HELPER] = method(HELPER, [
        Instruction(0, 'sput-object', [0], target=field),
        Instruction(2, 'sget-object', [2], defs=[2], target=field),
        Instruction(4, 'invoke-virtual', [1, 2], target=SINK), Instruction(10, 'return-void')], [0])
    f = run(flow_program, {ENTRY})[0][0]
    assert f.confidence == 'MEDIUM'
    assert any('field read' in s['label'] for s in f.data_flow)


def test_contexts_do_not_mix_arguments(flow_program):
    # The tainted value is passed to an unrelated call, not the sink wrapper.
    flow_program.methods[ENTRY].instructions[5].target = 'Ltest/Other;->ignore(Ljava/lang/String;)V'
    assert not run(flow_program, {ENTRY})[0]


def test_budget_is_visible(flow_program):
    findings, diagnostics = run(flow_program, {ENTRY}, max_steps=1)
    assert not findings and any('budget' in s for s in diagnostics)


def test_cancelled(flow_program):
    cancel = Cancellation()
    cancel.cancel()
    with pytest.raises(Cancelled):
        FlowEngine(RuleRegistry()).analyze(flow_program, {ENTRY}, cancel)


def test_constant_api_use_is_only_review(flow_program):
    from analyzer.analyzers.security import api_reviews
    reviews = api_reviews(flow_program, RuleRegistry())
    assert reviews and all(f.type == 'REVIEW' and f.severity == 'INFO' for f in reviews)


def test_inherited_getintent_reference(flow_program):
    flow_program.class_hierarchy = {'Ltest/Main;': 'Landroid/app/Activity;'}
    flow_program.methods[ENTRY].instructions[0].target = 'Ltest/Main;->getIntent()Landroid/content/Intent;'
    assert run(flow_program, {ENTRY})[0][0].analysis_level == 'L5'


def test_local_override_is_not_external_source(flow_program):
    override = 'Ltest/Main;->getIntent()Landroid/content/Intent;'
    flow_program.class_hierarchy = {'Ltest/Main;': 'Landroid/app/Activity;'}
    flow_program.methods[ENTRY].instructions[0].target = override
    flow_program.methods[override] = method(override, [Instruction(0, 'return-object', [0])], [0])
    f = run(flow_program, {ENTRY})[0][0]
    assert f.analysis_level == 'L4' and f.verification == 'POTENTIAL'


def test_untainted_library_work_does_not_starve_source_path(flow_program):
    noisy = 'Llib/Noise;->work()V'
    flow_program.methods[noisy] = method(noisy, [
        Instruction(0, 'goto', successors=[0])])
    root = flow_program.methods[ENTRY]
    root.instructions.insert(0, Instruction(-2, 'invoke-static', target=noisy, successors=[0]))
    engine = FlowEngine(RuleRegistry(), max_steps=100)
    findings, _ = engine.analyze(flow_program, {ENTRY}, Cancellation())
    assert findings[0].analysis_level == 'L5'
    assert engine.stats['skipped_untainted_calls'] >= 1


def test_source_reachable_callee_is_not_pruned():
    leaf = 'Ltest/Source;->read()Ljava/lang/String;'
    root = 'Ltest/Use;->run()V'
    program = Program(methods={
        leaf: method(leaf, [Instruction(0, 'invoke-virtual', [0, 1], target=SOURCE),
                           Instruction(6, 'move-result-object', [2], defs=[2]),
                           Instruction(8, 'return-object', [2])]),
        root: method(root, [Instruction(0, 'invoke-static', target=leaf),
                           Instruction(6, 'move-result-object', [2], defs=[2]),
                           Instruction(8, 'invoke-virtual', [1, 2], target=SINK),
                           Instruction(14, 'return-void')])})
    findings, _ = run(program)
    assert findings and findings[0].analysis_level == 'L4'


def test_uncertain_entry_never_establishes_l5(flow_program):
    engine = FlowEngine(RuleRegistry())
    findings, _ = engine.analyze(flow_program, {ENTRY}, Cancellation(), uncertain_entries={ENTRY})
    assert findings and all(f.analysis_level != 'L5' for f in findings)
    assert all(f.verification == 'POTENTIAL' and f.confidence == 'MEDIUM' for f in findings)


@pytest.mark.parametrize('target,registers,expected', [
    ('Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;', [1, 0], False),
    ('Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;', [0, 1], True),
    ('Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;', [0, 1], True),
    ('Landroid/os/Bundle;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', [1, 2, 0], True),
    ('Landroid/os/Bundle;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', [1, 0, 2], False),
    ('Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;', [1, 0], False),
    ('Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;', [0, 1], True),
    ('Landroid/net/Uri;->getHost()Ljava/lang/String;', [0], True),
    ('Landroid/net/Uri;->getFragment()Ljava/lang/String;', [0], True),
    ('Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;', [0], True),
    ('Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;', [1, 0], True),
    ('Ltest/Custom;->getHost()Ljava/lang/String;', [0], False),
])
def test_transfer_argument_precision(flow_program, target, registers, expected):
    flow_program.methods[HELPER] = method(HELPER, [
        Instruction(0, 'invoke-virtual', registers, target=target),
        Instruction(6, 'move-result-object', [3], defs=[3]),
        Instruction(8, 'invoke-virtual', [1, 3], target=SINK),
        Instruction(14, 'return-void')], [0])
    findings, _ = run(flow_program, {ENTRY})
    assert bool(findings) is expected


@pytest.mark.parametrize('target,registers,rule', [
    ('Landroid/webkit/WebView;->loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V',
     [1, 2, 0, 3, 4, 5], 'AOS-WEBVIEW-005'),
    ('Landroid/webkit/WebView;->loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V',
     [1, 0, 2, 3, 4, 5], 'AOS-WEBVIEW-004'),
    ('Landroid/webkit/WebView;->loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V',
     [1, 2, 3, 4, 5, 0], None),
    ('Landroid/webkit/WebView;->evaluateJavascript(Ljava/lang/String;Landroid/webkit/ValueCallback;)V',
     [1, 0, 2], 'AOS-WEBVIEW-006'),
    ('Landroid/webkit/WebView;->evaluateJavascript(Ljava/lang/String;Landroid/webkit/ValueCallback;)V',
     [1, 2, 0], None),
])
def test_webview_sensitive_argument_positions(flow_program, target, registers, rule):
    flow_program.methods[HELPER] = method(HELPER, [
        Instruction(0, 'invoke-virtual', registers, target=target), Instruction(6, 'return-void')], [0])
    findings, _ = run(flow_program, {ENTRY})
    assert {f.rule_id for f in findings} == ({rule} if rule else set())
    assert all(f.verification != 'CONFIRMED' for f in findings)
