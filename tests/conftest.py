import pytest
from analyzer.core.models import Instruction, Method, Program

ENTRY = 'Ltest/Main;->onCreate(Landroid/os/Bundle;)V'
HELPER = 'Ltest/Nav;->open(Ljava/lang/String;)V'
INTENT = 'Landroid/app/Activity;->getIntent()Landroid/content/Intent;'
SOURCE = 'Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;'
SINK = 'Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V'


def method(signature, instructions, params=None):
    for n, ins in enumerate(instructions[:-1]):
        if not ins.successors and not ins.opcode.startswith(('return', 'goto')):
            ins.successors = [instructions[n + 1].offset]
    return Method(signature, signature.split('->')[0], params or [], instructions)


@pytest.fixture
def flow_program():
    entry = method(ENTRY, [
        Instruction(0, 'invoke-virtual', [5], target=INTENT),
        Instruction(6, 'move-result-object', [0], defs=[0]),
        Instruction(8, 'const-string', [1], defs=[1], literal='url'),
        Instruction(12, 'invoke-virtual', [0, 1], target=SOURCE),
        Instruction(18, 'move-result-object', [2], defs=[2]),
        Instruction(20, 'invoke-static', [2], target=HELPER),
        Instruction(26, 'return-void'),
    ], [5, 6])
    helper = method(HELPER, [
        Instruction(0, 'invoke-virtual', [1, 0], target=SINK),
        Instruction(6, 'return-void'),
    ], [0])
    return Program(methods={ENTRY: entry, HELPER: helper}, classes=['Ltest/Main;', 'Ltest/Nav;'])
