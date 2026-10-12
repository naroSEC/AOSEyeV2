import pytest
from analyzer.core.models import Instruction as I
from analyzer.core.dataflow import FlowEngine
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from conftest import ENTRY, HELPER, SINK, method

TASK = 'Ltest/Task;'
FIELD = TASK + '->value:Ljava/lang/String;'
CTOR = TASK + '-><init>(Ljava/lang/String;)V'
RUN = TASK + '->run()V'
POST = 'Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z'
INTENT = 'Landroid/content/Intent;'
DEST = 'Ltest/Destination;'
CREATE = DEST + '->onCreate(Landroid/os/Bundle;)V'
START = 'Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V'
PUT = INTENT + '->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;'
GET = INTENT + '->getStringExtra(Ljava/lang/String;)Ljava/lang/String;'


def analyze(program, manifest=None):
    engine = FlowEngine(RuleRegistry())
    findings, diagnostics = engine.analyze(program, {ENTRY}, Cancellation(), manifest)
    return findings, diagnostics, engine


def task(program, extra=None, scheduler=POST):
    program.methods[CTOR] = method(CTOR, [I(0, 'iput-object', [1, 0], target=FIELD),
                                         I(2, 'return-void')], [0, 1])
    program.methods[RUN] = method(RUN, [I(0, 'iget-object', [1, 0], defs=[1], target=FIELD),
        I(2, 'invoke-virtual', [9, 1], target=SINK), I(8, 'return-void')], [0])
    instructions = [I(0, 'new-instance', [1], defs=[1], literal=TASK),
                    I(2, 'invoke-direct', [1, 0], target=CTOR)]
    instructions += extra or []
    instructions += [I(30, 'invoke-virtual', [9, 1], target=scheduler), I(36, 'return-void')]
    program.methods[HELPER] = method(HELPER, instructions, [0])


@pytest.mark.parametrize('scheduler', [POST,
    'Landroid/view/View;->post(Ljava/lang/Runnable;)Z',
    'Landroid/app/Activity;->runOnUiThread(Ljava/lang/Runnable;)V',
    'Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V'])
def test_captured_field_reaches_concrete_callback(flow_program, scheduler):
    task(flow_program, scheduler=scheduler)
    findings, diagnostics, engine = analyze(flow_program)
    f = next(f for f in findings if f.location.method == RUN)
    assert f.analysis_level == 'L5' and f.verification == 'POTENTIAL' and f.confidence == 'MEDIUM'
    assert any('ASYNC boundary' in s['label'] for s in f.data_flow)
    assert any(b['status'] == 'MODELED_POTENTIAL' for b in engine.stats['boundaries'])
    assert any('scheduling' in d for d in diagnostics)


def test_same_class_instances_do_not_share_capture(flow_program):
    task(flow_program, [I(8, 'new-instance', [1], defs=[1], literal=TASK),
                        I(10, 'const-string', [2], defs=[2], literal='safe'),
                        I(12, 'invoke-direct', [1, 2], target=CTOR)])
    assert not analyze(flow_program)[0]


def test_capture_overwrite_kills_old_taint(flow_program):
    task(flow_program, [I(8, 'const-string', [2], defs=[2], literal='safe'),
                        I(10, 'iput-object', [2, 1], target=FIELD)])
    assert not analyze(flow_program)[0]


def test_moved_callback_alias_retains_identity(flow_program):
    task(flow_program, [I(8, 'move-object', [2, 1], defs=[2]),
                        I(10, 'const', [1], defs=[1], literal=0),
                        I(12, 'move-object', [1, 2], defs=[1])])
    assert any(f.location.method == RUN for f in analyze(flow_program)[0])


def test_unknown_callback_is_not_guessed(flow_program):
    task(flow_program, [I(8, 'const', [1], defs=[1], literal=0)])
    findings, diagnostics, engine = analyze(flow_program)
    assert not findings
    assert any('Unresolved ASYNC' in d for d in diagnostics)


def icc(program, extra=None, read_key='url', enabled=True, target=DEST):
    program.methods[HELPER] = method(HELPER, [
        I(0, 'new-instance', [1], defs=[1], literal=INTENT),
        I(2, 'const-class', [2], defs=[2], literal=target),
        I(4, 'invoke-direct', [1, 9, 2], target=INTENT + '-><init>(Landroid/content/Context;Ljava/lang/Class;)V'),
        I(10, 'const-string', [3], defs=[3], literal='url'),
        I(12, 'invoke-virtual', [1, 3, 0], target=PUT),
        *(extra or []), I(40, 'invoke-virtual', [9, 1], target=START), I(46, 'return-void')], [0])
    program.methods[CREATE] = method(CREATE, [
        I(0, 'invoke-virtual', [5], target='Landroid/app/Activity;->getIntent()Landroid/content/Intent;'),
        I(6, 'move-result-object', [0], defs=[0]),
        I(8, 'const-string', [1], defs=[1], literal=read_key),
        I(10, 'invoke-virtual', [0, 1], target=GET),
        I(16, 'move-result-object', [2], defs=[2]),
        I(18, 'invoke-virtual', [9, 2], target=SINK), I(24, 'return-void')], [5, 6])
    return {'components': [dict(name='test.Destination', target='test.Destination', kind='activity',
                                 enabled=enabled, exported=False, permission='', attributes={})]}


def linked(findings):
    return [f for f in findings if any('ICC boundary' in s['label'] for s in f.data_flow)]


def test_explicit_internal_intent_preserves_extra_provenance(flow_program):
    manifest = icc(flow_program)
    findings, diagnostics, engine = analyze(flow_program, manifest)
    f = linked(findings)[0]
    assert f.location.method == CREATE and f.analysis_level == 'L5'
    assert f.verification == 'POTENTIAL' and f.confidence == 'MEDIUM'
    assert any('Intent extra read' in s['label'] for s in f.data_flow)


@pytest.mark.parametrize('options', [dict(read_key='different'), dict(enabled=False), dict(target='Lother/App;')])
def test_icc_mismatch_does_not_fabricate_path(flow_program, options):
    manifest = icc(flow_program, **options)
    assert not linked(analyze(flow_program, manifest)[0])


def test_overwritten_extra_does_not_reach_component(flow_program):
    manifest = icc(flow_program, [I(20, 'const-string', [4], defs=[4], literal='safe'),
                                I(22, 'invoke-virtual', [1, 3, 4], target=PUT)])
    assert not linked(analyze(flow_program, manifest)[0])


def test_async_effects_do_not_become_synchronous_returns(flow_program):
    task(flow_program)
    flow_program.methods[RUN].instructions = [I(0, 'return-void')]
    flow_program.methods[HELPER] = method(HELPER,
        flow_program.methods[HELPER].instructions[:-1] + [
            I(36, 'move-result-object', [2], defs=[2]),
            I(38, 'invoke-virtual', [9, 2], target=SINK), I(44, 'return-void')], [0])
    assert not analyze(flow_program)[0]


def test_object_factory_calls_have_distinct_allocation_identities(flow_program):
    task(flow_program)
    factory = 'Ltest/Factory;->make(Ljava/lang/String;)Ljava/lang/Runnable;'
    flow_program.methods[factory] = method(factory, [
        I(0, 'new-instance', [1], defs=[1], literal=TASK),
        I(2, 'invoke-direct', [1, 0], target=CTOR), I(8, 'return-object', [1])], [0])
    flow_program.methods[HELPER] = method(HELPER, [
        I(0, 'invoke-static', [0], target=factory), I(6, 'move-result-object', [1], defs=[1]),
        I(8, 'const-string', [2], defs=[2], literal='safe'),
        I(10, 'invoke-static', [2], target=factory), I(16, 'move-result-object', [2], defs=[2]),
        I(18, 'invoke-virtual', [9, 1], target=POST), I(24, 'return-void')], [0])
    assert any(f.location.method == RUN for f in analyze(flow_program)[0])
    flow_program.methods[HELPER].instructions[-2].registers = [9, 2]
    assert not analyze(flow_program)[0]


def test_unknown_extra_key_invalidates_stale_payload(flow_program):
    manifest = icc(flow_program, [I(20, 'const-string', [4], defs=[4], literal='safe'),
                                 I(22, 'invoke-virtual', [1, 8, 4], target=PUT)])
    findings, diagnostics, _ = analyze(flow_program, manifest)
    assert not linked(findings)
    assert any('Unknown Intent extra key' in d for d in diagnostics)


def test_unknown_intent_mutator_invalidates_stale_target(flow_program):
    manifest = icc(flow_program, [I(20, 'invoke-virtual', [1, 8],
        target=INTENT + '->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;')])
    findings, diagnostics, _ = analyze(flow_program, manifest)
    assert not linked(findings)
    assert any('Unresolved ICC' in d for d in diagnostics)


def test_boundary_inventory_does_not_reduce_primary_root_budget(flow_program):
    for n in range(300):
        sig = f'Llibrary/Noise{n};->schedule()V'
        flow_program.methods[sig] = method(sig, [I(0, 'invoke-virtual', [0, 1], target=POST),
                                                I(6, 'return-void')])
    engine = FlowEngine(RuleRegistry(), max_steps=100)
    findings, _ = engine.analyze(flow_program, {ENTRY}, Cancellation())
    assert any(f.analysis_level == 'L5' for f in findings)
    assert engine.stats['primary_candidate_roots'] == engine.stats['primary_explored_roots'] == 1
    assert engine.stats['candidate_roots'] == 301


def test_string_is_not_a_component_class_constant(flow_program):
    manifest = icc(flow_program)
    flow_program.methods[HELPER].instructions[1].opcode = 'const-string'
    assert not linked(analyze(flow_program, manifest)[0])


def test_intent_alias_uses_same_payload(flow_program):
    manifest = icc(flow_program, [I(20, 'move-object', [4, 1], defs=[4]),
                                I(22, 'const', [1], defs=[1], literal=0),
                                I(24, 'move-object', [1, 4], defs=[1])])
    assert linked(analyze(flow_program, manifest)[0])


def test_inherited_runnable_implementation_is_resolved(flow_program):
    task(flow_program)
    child = 'Ltest/ChildTask;'
    flow_program.class_hierarchy[child] = TASK
    flow_program.methods[HELPER].instructions[0].literal = child
    assert any(f.location.method == RUN for f in analyze(flow_program)[0])


def test_local_post_override_is_not_a_framework_scheduler(flow_program):
    local = 'Ltest/MyHandler;->post(Ljava/lang/Runnable;)Z'
    flow_program.class_hierarchy['Ltest/MyHandler;'] = 'Landroid/os/Handler;'
    flow_program.methods[local] = method(local, [I(0, 'return', [0])], [0, 1])
    task(flow_program, scheduler=local)
    findings, _, engine = analyze(flow_program)
    assert not findings and not engine.stats['boundaries']


def test_setclass_fluent_result_preserves_intent_alias(flow_program):
    manifest = icc(flow_program)
    body = flow_program.methods[HELPER].instructions
    body[2].opcode = 'invoke-virtual'
    body[2].target = INTENT + '->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;'
    body[2].successors = [9]
    body.insert(3, I(9, 'move-result-object', [1], defs=[1], successors=[10]))
    assert linked(analyze(flow_program, manifest)[0])


def test_intent_data_roundtrip_preserves_provenance(flow_program):
    manifest = icc(flow_program)
    body = flow_program.methods[HELPER].instructions
    body[4].target = INTENT + '->setData(Landroid/net/Uri;)Landroid/content/Intent;'
    body[4].registers = [1, 0]
    receiver = flow_program.methods[CREATE].instructions
    receiver[3].target = INTENT + '->getDataString()Ljava/lang/String;'
    receiver[3].registers = [0]
    assert linked(analyze(flow_program, manifest)[0])


def test_callback_heap_writes_are_not_synchronous_caller_effects(flow_program):
    task(flow_program)
    shared = 'Ltest/Shared;->value:Ljava/lang/String;'
    flow_program.methods[RUN] = method(RUN, [
        I(0, 'iget-object', [1, 0], defs=[1], target=FIELD),
        I(2, 'sput-object', [1], target=shared), I(4, 'return-void')], [0])
    body = flow_program.methods[HELPER].instructions[:-1]
    flow_program.methods[HELPER] = method(HELPER, body + [
        I(36, 'sget-object', [2], defs=[2], target=shared),
        I(38, 'invoke-virtual', [9, 2], target=SINK), I(44, 'return-void')], [0])
    assert not analyze(flow_program)[0]
