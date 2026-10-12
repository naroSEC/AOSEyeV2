import pytest
from analyzer.core.models import Instruction as I
from conftest import HELPER, SINK, method
from test_boundaries import icc, analyze, linked, CREATE, DEST, GET


@pytest.mark.parametrize('kind,member', [
    ('service', 'startService(Landroid/content/Intent;)Landroid/content/ComponentName;'),
    ('service', 'startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;'),
    ('receiver', 'sendBroadcast(Landroid/content/Intent;)V'),
    ('receiver', 'sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V')])
@pytest.mark.parametrize('change', ['positive', 'other_key', 'disabled', 'wrong_kind', 'missing_body', 'malformed_params'])
def test_explicit_component_delivery(flow_program, kind, member, change):
    manifest = icc(flow_program)
    component = manifest['components'][0]
    component['kind'] = kind if change != 'wrong_kind' else 'activity'
    component['enabled'] = change != 'disabled'
    flow_program.methods[HELPER].instructions[-2].target = 'Landroid/content/Context;->' + member
    if 'Ljava/lang/String;' in member:
        flow_program.methods[HELPER].instructions[-2].registers.append(7)
    del flow_program.methods[CREATE]
    callback = DEST + ('->onStartCommand(Landroid/content/Intent;II)I' if kind == 'service' else
                      '->onReceive(Landroid/content/Context;Landroid/content/Intent;)V')
    # Distinct DEX register for incoming Intent in each lifecycle contract.
    incoming = 6 if kind == 'service' else 7
    params = [5, 6, 7, 8] if kind == 'service' else [5, 6, 7]
    if change != 'missing_body':
        flow_program.methods[callback] = method(callback, [
            I(0, 'const-string', [1], literal='other' if change == 'other_key' else 'url', defs=[1]),
            I(2, 'invoke-virtual', [incoming, 1], target=GET),
            I(8, 'move-result-object', [0], defs=[0]), I(10, 'invoke-virtual', [9, 0], target=SINK),
            I(16, 'return-void')], params if change != 'malformed_params' else [])
    findings, _, engine = analyze(flow_program, manifest)
    result = linked(findings)
    assert bool(result) == (change == 'positive')
    if result:
        assert all(f.location.method == callback and f.verification == 'POTENTIAL' for f in result)
        assert any(b['component_kind'] == kind and b['runtime_delivery'] == 'UNKNOWN'
                   for b in engine.stats['boundaries'])


@pytest.mark.parametrize('mutate_copy', [False, True])
def test_copied_intent_has_independent_payload(flow_program, mutate_copy):
    from test_boundaries import INTENT, PUT
    manifest = icc(flow_program)
    m = flow_program.methods[HELPER]
    extra = [I(20, 'new-instance', [4], defs=[4], literal=INTENT),
        I(22, 'invoke-direct', [4, 1], target=INTENT+'-><init>(Landroid/content/Intent;)V'),
        I(28, 'const-string', [5], defs=[5], literal='safe'),
        I(30, 'invoke-virtual', [4 if mutate_copy else 1, 3, 5], target=PUT)]
    m.instructions[-2].registers = [9, 4]
    code = m.instructions[:-2] + extra + m.instructions[-2:]
    for ins in code:
        ins.successors = []
    flow_program.methods[HELPER] = method(HELPER, code, [0])
    assert bool(linked(analyze(flow_program, manifest)[0])) == (not mutate_copy)


@pytest.mark.parametrize('package', ['test', 'other', None])
@pytest.mark.parametrize('class_name,expected', [('test.Destination', True), ('.Destination', False),
    ('test.Other', False), ('test/Destination', False), ('', False), (None, False)])
def test_explicit_set_class_name(flow_program, class_name, expected, package):
    from test_boundaries import INTENT
    manifest = icc(flow_program)
    manifest['package'] = 'test'
    m = flow_program.methods[HELPER]
    code = m.instructions[:-2] + [I(20, 'const-string', [6], literal=package),
        I(22, 'const-string', [7], literal=class_name),
        I(24, 'invoke-virtual', [1, 6, 7], target=INTENT+
          '->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;')] + m.instructions[-2:]
    for ins in code:
        ins.successors = []
    flow_program.methods[HELPER] = method(HELPER, code, [0])
    assert bool(linked(analyze(flow_program, manifest)[0])) == (expected and package == 'test')
