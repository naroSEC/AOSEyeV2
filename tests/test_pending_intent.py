import pytest
from analyzer.analyzers.pending_intent import pending_intent_context, INTENT, CALLS, MUTABLE, IMMUTABLE, UNSAFE, NO_CREATE
from analyzer.core.models import Instruction as I, Program, AnalysisResult
from analyzer.app.jobs import Cancellation, Cancelled
from conftest import method
from analyzer.analyzers.pending_intent import CLASS_SETTERS

CLEAR = INTENT + '->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;'
COPY = INTENT + '-><init>(Landroid/content/Intent;)V'


def program(flags=MUTABLE, extra=(), target=None):
    target = target or next(iter(CALLS))
    m = method('Ltest/P;->run()V', [I(0, 'new-instance', [0], literal=INTENT),
        I(2, 'invoke-direct', [0], target=INTENT + '-><init>()V'),
        I(8, 'const', [1], literal=flags), *extra,
        I(40, 'invoke-static', [8, 9, 0, 1] + ([7] if CALLS[target] == 5 else []), target=target)])
    return Program(methods={m.signature: m})


@pytest.mark.parametrize('target', CALLS)
@pytest.mark.parametrize('opcode', ['invoke-static', 'invoke-static/range'])
def test_mutable_unconstrained(target, opcode):
    p = program(target=target)
    next(iter(p.methods.values())).instructions[-1].opcode = opcode
    f, = pending_intent_context(p, {'target_sdk': 35}, Cancellation())
    assert f.rule_id == 'AOS-IPC-005' and f.type == 'REVIEW'
    assert f.verification == 'MANUAL_REVIEW' and not f.attack_path
    assert f.validation['platform_behavior'] == 'MAY_REJECT_ON_API_34_PLUS'
    assert f.location.offset == 40
    result = AnalysisResult('test.apk', '0' * 64, findings=[f], program=p)
    assert AnalysisResult.from_dict(result.to_dict()).findings[0].id == f.id


@pytest.mark.parametrize('flags', [0, IMMUTABLE, NO_CREATE | MUTABLE, None, True, '33554432', 1 << 32])
def test_other_unknown_or_lookup_only_flags(flags):
    assert not pending_intent_context(program(flags), {}, Cancellation())


def test_conflict_and_unsafe_override():
    f, = pending_intent_context(program(MUTABLE | IMMUTABLE), {}, Cancellation())
    assert f.rule_id == 'AOS-IPC-006' and f.severity == 'INFO'
    f, = pending_intent_context(program(MUTABLE | UNSAFE), {'target_sdk': 35}, Cancellation())
    assert f.validation['platform_behavior'] == 'UNSAFE_IMPLICIT_FLAG_PRESENT'


def test_package_restriction_then_null_removal():
    extra = [I(10, 'const-string', [2], literal='test.package'),
        I(12, 'invoke-virtual', [0, 2], target=INTENT + '->setPackage(Ljava/lang/String;)Landroid/content/Intent;')]
    assert not pending_intent_context(program(extra=extra), {}, Cancellation())
    extra += [I(18, 'const/4', [2], literal=0),
        I(20, 'invoke-virtual', [0, 2], target=INTENT + '->setPackage(Ljava/lang/String;)Landroid/content/Intent;')]
    assert len(pending_intent_context(program(extra=extra), {}, Cancellation())) == 1


def test_explicit_constructor():
    p = program()
    m = next(iter(p.methods.values()))
    m.instructions.insert(1, I(1, 'const-class', [3], literal='Ltest/Target;'))
    m.instructions[2].target = INTENT + '-><init>(Landroid/content/Context;Ljava/lang/Class;)V'
    m.instructions[2].registers = [0, 8, 3]
    assert not pending_intent_context(p, {}, Cancellation())


@pytest.mark.parametrize('extra', [[I(10, 'move-object', [0, 7])],
    [I(10, 'invoke-static', [0], target='Lunknown/A;->mutate(Landroid/content/Intent;)V')],
    [I(10, 'if-eqz', [7])], [I(10, 'move', [1, 7])]])
def test_unknown_mutations_or_branch_do_not_reuse_state(extra):
    assert not pending_intent_context(program(extra=extra), {}, Cancellation())


def test_alias_and_fluent_action_result():
    p = program(extra=[I(10, 'move-object', [2, 0]),
        I(12, 'invoke-virtual', [2, 8], target=INTENT + '->setAction(Ljava/lang/String;)Landroid/content/Intent;'),
        I(18, 'move-result-object', [0])])
    assert len(pending_intent_context(p, {}, Cancellation())) == 1


def test_cfg_reset_and_cancellation():
    p = program()
    next(iter(p.methods.values())).cfg = [{'offsets': [0, 2, 8]}, {'offsets': [40]}]
    assert not pending_intent_context(p, {}, Cancellation())
    cancel = Cancellation()
    cancel.cancel()
    with pytest.raises(Cancelled):
        pending_intent_context(p, {}, cancel)


@pytest.mark.parametrize('target', CLASS_SETTERS)
@pytest.mark.parametrize('opcode', ['invoke-virtual', 'invoke-virtual/range'])
def test_setter_then_component_clear(target, opcode):
    kind, _ = CLASS_SETTERS[target]
    extra = [I(10, 'const-string', [2], literal='test.package'),
        I(12, 'const-class' if kind == 'class' else 'const-string', [3], literal='Ltest/Target;' if kind == 'class' else 'test.Target'),
        I(14, opcode, [0, 2, 3], target=target)]
    assert not pending_intent_context(program(extra=extra), {}, Cancellation())
    extra += [I(20, 'const/4', [4], literal=0), I(22, opcode, [0, 4], target=CLEAR)]
    assert len(pending_intent_context(program(extra=extra), {}, Cancellation())) == 1


@pytest.mark.parametrize('value', [None, '', 0])
def test_unresolved_class_name_does_not_become_known_implicit(value):
    target = list(CLASS_SETTERS)[1]
    extra = [I(10, 'const-string', [3], literal=value), I(12, 'invoke-virtual', [0, 8, 3], target=target),
             I(18, 'const/4', [4], literal=0), I(20, 'invoke-virtual', [0, 4], target=CLEAR)]
    assert not pending_intent_context(program(extra=extra), {}, Cancellation())


def test_clear_component_preserves_package_restriction():
    extra = [I(10, 'const-string', [2], literal='test.package'),
        I(12, 'invoke-virtual', [0, 2], target=INTENT + '->setPackage(Ljava/lang/String;)Landroid/content/Intent;'),
        I(18, 'const/4', [4], literal=0), I(20, 'invoke-virtual', [0, 4], target=CLEAR)]
    assert not pending_intent_context(program(extra=extra), {}, Cancellation())


@pytest.mark.parametrize('original_explicit', [True, False])
def test_copy_has_independent_destination_state(original_explicit):
    extra = [I(10, 'const-class', [3], literal='Ltest/Target;')]
    if original_explicit:
        extra += [I(12, 'invoke-virtual', [0, 8, 3], target=next(iter(CLASS_SETTERS)))]
    extra += [I(18, 'new-instance', [6], literal=INTENT), I(20, 'invoke-direct', [6, 0], target=COPY)]
    if original_explicit:
        extra += [I(26, 'const/4', [4], literal=0), I(28, 'invoke-virtual', [0, 4], target=CLEAR)]
    else:
        extra += [I(26, 'invoke-virtual', [0, 8, 3], target=next(iter(CLASS_SETTERS)))]
    p = program(extra=extra)
    next(iter(p.methods.values())).instructions[-1].registers[2] = 6
    assert bool(pending_intent_context(p, {}, Cancellation())) is not original_explicit


def test_unknown_component_and_unknown_copy_do_not_guess_state():
    assert not pending_intent_context(program(extra=[I(10, 'invoke-virtual', [0, 8], target=CLEAR)]), {}, Cancellation())
    assert not pending_intent_context(program(extra=[I(10, 'invoke-direct', [0, 8], target=COPY)]), {}, Cancellation())
