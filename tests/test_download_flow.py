import pytest
from analyzer.analyzers.download_flow import download_flows
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.core.models import Instruction as I, Program, AnalysisResult
from conftest import method

SOURCE = 'Landroid/app/DownloadManager;->getUriForDownloadedFile(J)Landroid/net/Uri;'
PATH = 'Landroid/net/Uri;->getPath()Ljava/lang/String;'
SINK = 'Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V'


def program(variant='positive'):
    instructions = [I(0, 'invoke-virtual', [8, 9, 10], target=SOURCE),
        I(6, 'move-result-object', [0], defs=[0]), I(8, 'invoke-virtual', [0], target=PATH),
        I(14, 'move-result-object', [1], defs=[1]),
        I(20, 'invoke-direct', [2, 1, 3, 4, 5], target=SINK), I(26, 'return-void')]
    if variant == 'wrong_argument':
        instructions[-2].registers = [2, 3, 1, 4, 5]
    elif variant == 'overwrite':
        instructions.insert(-2, I(16, 'const-string', [1], defs=[1], literal='fixed.apk'))
    elif variant == 'unrelated_source':
        instructions[0].target = 'Ltest/Other;->getUriForDownloadedFile(J)Landroid/net/Uri;'
    elif variant == 'unknown_transform':
        instructions[2].target = 'Ltest/Other;->decode()Ljava/lang/String;'
    m = method('Ltest/Download;->run()V', instructions)
    return Program(methods={m.signature: m})


def test_download_uri_path_is_manual_candidate():
    p = program()
    findings, _, coverage = download_flows(p, Cancellation())
    f, = findings
    assert f.rule_id == 'AOS-DYNAMIC-003' and f.type == 'REVIEW' and not f.attack_path
    assert f.verification == 'MANUAL_REVIEW' and f.validation['filesystem_path_validity'] == 'UNKNOWN'
    assert f.validation['required_conditions'] == 'MET' and coverage['steps'] > 0
    result = AnalysisResult('test.apk', '0' * 64, findings=findings, program=p)
    assert AnalysisResult.from_dict(result.to_dict()).findings[0].id == f.id


@pytest.mark.parametrize('variant', ['wrong_argument', 'overwrite', 'unrelated_source', 'unknown_transform'])
def test_negative_patterns(variant):
    findings, _, _ = download_flows(program(variant), Cancellation())
    assert not findings


def test_zero_budget():
    findings, diagnostics, coverage = download_flows(program(), Cancellation(), max_steps=0)
    assert not findings and diagnostics and coverage['steps'] == 0


def test_cancel():
    cancel = Cancellation()
    cancel.cancel()
    with pytest.raises(Cancelled):
        download_flows(program(), cancel)
