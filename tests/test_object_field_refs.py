import pytest
from analyzer.core.models import Instruction as I
from conftest import HELPER, SINK, method
from test_boundaries import TASK, RUN, POST, INTENT, PUT, GET, analyze

FIELD = TASK + '->intent:Landroid/content/Intent;'


@pytest.mark.parametrize('change', ['positive', 'overwrite', 'escape_holder', 'escape_intent', 'cycle'])
def test_intent_reference_captured_by_callback(flow_program, change):
    flow_program.methods[RUN] = method(RUN, [I(0, 'iget-object', [1, 0], defs=[1], target=FIELD),
        I(2, 'const-string', [2], defs=[2], literal='url'), I(4, 'invoke-virtual', [1, 2], target=GET),
        I(10, 'move-result-object', [3], defs=[3]), I(12, 'invoke-virtual', [9, 3], target=SINK),
        I(18, 'return-void')], [0])
    extra = []
    if change == 'overwrite': extra = [I(22, 'const/4', [4], literal=0), I(24, 'iput-object', [4, 3], target=FIELD)]
    if change.startswith('escape'):
        extra = [I(24, 'invoke-static', [3 if change == 'escape_holder' else 1], target='Lunknown;->mutate(Ljava/lang/Object;)V')]
    if change == 'cycle':
        extra = [I(22, 'iput-object', [3, 3], target=TASK+'->self:Ljava/lang/Object;'),
                 I(24, 'invoke-static', [3], target='Lunknown;->mutate(Ljava/lang/Object;)V')]
    flow_program.methods[HELPER] = method(HELPER, [
        I(0, 'new-instance', [1], defs=[1], literal=INTENT),
        I(2, 'invoke-direct', [1], target=INTENT+'-><init>()V'),
        I(8, 'const-string', [2], defs=[2], literal='url'),
        I(10, 'invoke-virtual', [1, 2, 0], target=PUT),
        I(16, 'new-instance', [3], defs=[3], literal=TASK),
        I(18, 'iput-object', [1, 3], target=FIELD), *extra,
        I(30, 'invoke-virtual', [9, 3], target=POST), I(36, 'return-void')], [0])
    findings, _, _ = analyze(flow_program)
    assert any(f.location.method == RUN and any('ASYNC boundary' in step['label'] for step in f.data_flow)
               for f in findings) == (change == 'positive')
