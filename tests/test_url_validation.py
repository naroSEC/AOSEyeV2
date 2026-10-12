import pytest
from analyzer.core.models import Program, Method, Instruction as I, Finding, Location
from analyzer.analyzers.url_validation import url_guard_review, PARSE, EQUALS
from analyzer.analyzers.verification import CandidateReviewer

SIG = 'Ltest/Guard;->open(Ljava/lang/String;Ljava/lang/String;)V'
SINK = 'Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V'


@pytest.fixture
def guarded():
    code = [I(0, 'invoke-static', [0], target=PARSE),
            I(1, 'move-result-object', [1], defs=[1]),
            I(2, 'invoke-virtual', [1], target='Landroid/net/Uri;->getScheme()Ljava/lang/String;'),
            I(3, 'move-result-object', [2], defs=[2]), I(4, 'const-string', [3], defs=[3], literal='https'),
            I(5, 'invoke-virtual', [3, 2], target=EQUALS), I(6, 'move-result', [4], defs=[4]),
            I(7, 'if-eqz', [4], successors=[8, 30]),
            I(8, 'invoke-virtual', [1], target='Landroid/net/Uri;->getHost()Ljava/lang/String;'),
            I(9, 'move-result-object', [2], defs=[2]), I(10, 'const-string', [3], defs=[3], literal='trusted.example'),
            I(11, 'invoke-virtual', [2, 3], target=EQUALS), I(12, 'move-result', [4], defs=[4]),
            I(13, 'if-eqz', [4], successors=[14, 30]),
            I(14, 'invoke-virtual', [8, 0], target=SINK), I(15, 'return-void'), I(30, 'return-void')]
    for current, following in zip(code, code[1:]):
        if not current.successors and not current.opcode.startswith('return'):
            current.successors = [following.offset]
    return Program(methods={SIG: Method(SIG, parameter_registers=[0, 7, 8], instructions=code, exception_status='NONE')})


def review(program, **kwargs):
    return url_guard_review(program, SIG, 14, **kwargs)


def test_exact_components_same_value_all_paths(guarded):
    report = review(guarded)
    assert report['status'] == 'NORMAL_FLOW_CONSTRAINED'
    assert report['scheme_allowlist'] == report['host_allowlist'] == 'MODELED_EXACT_MATCH'
    assert report['sink_paths'] == 1
    assert {e['allowed_literal'] for e in report['evidence']} == {'https', 'trusted.example'}


def test_annotation_does_not_suppress_or_downgrade_finding(guarded):
    finding = Finding('r', 'test', '', 'WEBVIEW', type='VULNERABILITY', severity='HIGH',
                      verification='LIKELY', location=Location(method=SIG, offset=14))
    CandidateReviewer(guarded, {}).annotate(finding)
    assert finding.validation['host_allowlist'] == 'MODELED_EXACT_MATCH'
    assert (finding.type, finding.severity, finding.verification) == ('VULNERABILITY', 'HIGH', 'LIKELY')


@pytest.mark.parametrize('offset', [7, 13])
def test_reversed_acceptance_is_unknown(guarded, offset):
    guarded.methods[SIG].instructions[offset].opcode = 'if-nez'
    report = review(guarded)
    assert report['scheme_allowlist' if offset == 7 else 'host_allowlist'] == 'UNKNOWN'


def test_check_on_other_value_is_unknown(guarded):
    guarded.methods[SIG].instructions[0].registers = [7]
    assert review(guarded)['status'] == 'UNKNOWN'


def test_prefix_comparison_is_not_exact_allowlist(guarded):
    guarded.methods[SIG].instructions[11].target = 'Ljava/lang/String;->startsWith(Ljava/lang/String;)Z'
    assert review(guarded)['host_allowlist'] == 'UNKNOWN'


def test_bypass_branch_is_not_sufficient(guarded):
    guarded.methods[SIG].instructions[13].successors = [14, 15]
    guarded.methods[SIG].instructions[15].opcode = 'goto'
    guarded.methods[SIG].instructions[15].successors = [14]
    assert review(guarded)['host_allowlist'] == 'UNKNOWN'


def test_reassignment_after_checks_does_not_validate_new_value(guarded):
    code = guarded.methods[SIG].instructions
    code[14].offset = 16
    code[14].successors = [18]
    code[15].offset = 18
    code.insert(14, I(14, 'move-object', [0, 7], defs=[0], successors=[16]))
    report = url_guard_review(guarded, SIG, 16)
    assert report['scheme_allowlist'] == report['host_allowlist'] == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['loop', 'exception', 'missing-edge', 'budget'])
def test_incomplete_model_never_proves_guard(guarded, kind):
    code = guarded.methods[SIG].instructions
    if kind == 'loop':
        code[-1].opcode, code[-1].successors = 'goto', [7]
    elif kind == 'exception':
        code[-1].opcode = 'move-exception'
    elif kind == 'missing-edge':
        code[7].successors = [8, 999]
    report = review(guarded, max_steps=0) if kind == 'budget' else review(guarded)
    assert report['status'] == 'UNKNOWN' and not report['evidence']


def test_successor_order_does_not_define_branch_direction(guarded):
    for offset in (7, 13):
        guarded.methods[SIG].instructions[offset].successors.reverse()
    assert review(guarded)['host_allowlist'] == 'MODELED_EXACT_MATCH'


HELPER = 'Ltest/Guard;->allowed(Ljava/lang/String;)Z'
CALLER = 'Ltest/Caller;->open(Ljava/lang/String;Ljava/lang/String;)V'


@pytest.fixture
def helper_guarded(guarded):
    helper = guarded.methods.pop(SIG)
    helper.signature = HELPER
    helper.parameter_registers = [0]
    helper.instructions[14] = I(14, 'const/4', [4], defs=[4], literal=1, successors=[15])
    helper.instructions[15] = I(15, 'return', [4])
    helper.instructions[-1] = I(30, 'const/4', [4], defs=[4], literal=0, successors=[31])
    helper.instructions.append(I(31, 'return', [4]))
    caller = Method(CALLER, parameter_registers=[0, 7, 8], exception_status='NONE', instructions=[
        I(0, 'invoke-static', [0], target=HELPER, successors=[1]),
        I(1, 'move-result', [2], defs=[2], successors=[2]),
        I(2, 'if-eqz', [2], successors=[3, 5]),
        I(3, 'invoke-virtual', [8, 0], target=SINK, successors=[4]),
        I(4, 'return-void'), I(5, 'return-void')])
    return Program(methods={HELPER: helper, CALLER: caller})


def test_boolean_helper_preserves_argument_identity(helper_guarded):
    report = url_guard_review(helper_guarded, CALLER, 3)
    assert report['host_allowlist'] == report['scheme_allowlist'] == 'MODELED_EXACT_MATCH'
    assert report['helper_calls'][0]['status'] == 'BOOLEAN_SUMMARY'
    assert all(e['method'] == HELPER for e in report['evidence'])


@pytest.mark.parametrize('case', ['different-input', 'inverted', 'ignored-result', 'virtual', 'true-on-rejection'])
def test_helper_bypasses_never_prove_validation(helper_guarded, case):
    caller = helper_guarded.methods[CALLER].instructions
    if case == 'different-input':
        caller[0].registers = [7]
    elif case == 'inverted':
        caller[2].opcode = 'if-nez'
    elif case == 'ignored-result':
        caller[2].opcode, caller[2].successors = 'goto', [3]
    elif case == 'virtual':
        caller[0].opcode = 'invoke-virtual'
    else:
        helper_guarded.methods[HELPER].instructions[-2].literal = 1
    report = url_guard_review(helper_guarded, CALLER, 3)
    assert report['host_allowlist'] == report['scheme_allowlist'] == 'UNKNOWN'


@pytest.mark.parametrize('owner', [CALLER, HELPER])
@pytest.mark.parametrize('status', ['PRESENT', 'UNKNOWN'])
def test_exception_tables_required_in_caller_and_helper(helper_guarded, owner, status):
    helper_guarded.methods[owner].exception_status = status
    report = url_guard_review(helper_guarded, CALLER, 3)
    assert report['status'] == 'UNKNOWN' and not report['evidence']


def test_helper_recursion_is_unknown(helper_guarded):
    helper = helper_guarded.methods[HELPER]
    helper.instructions = [I(0, 'invoke-static', [0], target=HELPER, successors=[1]),
                           I(1, 'move-result', [1], defs=[1], successors=[2]), I(2, 'return', [1])]
    assert url_guard_review(helper_guarded, CALLER, 3)['status'] == 'UNKNOWN'


def test_helper_budget_is_shared(helper_guarded):
    assert url_guard_review(helper_guarded, CALLER, 3, max_steps=5)['status'] == 'UNKNOWN'


def test_guard_review_serializable_with_helper_evidence(helper_guarded, tmp_path):
    from analyzer.app.project_manager import save_project, open_project
    from analyzer.core.models import AnalysisResult
    finding = Finding('r', 'test', '', 'WEBVIEW', location=Location(method=CALLER, offset=3))
    CandidateReviewer(helper_guarded, {}).annotate(finding)
    path = tmp_path / 'helper.json'
    save_project(path, AnalysisResult('fixture.apk', 'fixture', findings=[finding], program=helper_guarded))
    result = open_project(path)
    assert result.findings[0].review == finding.review
    assert result.program.methods[HELPER].exception_status == 'NONE'


def test_legacy_method_without_exception_metadata_stays_unknown(guarded):
    from dataclasses import asdict
    data = asdict(guarded)
    del data['methods'][SIG]['exception_status']
    assert review(Program.from_dict(data))['status'] == 'UNKNOWN'


def add_handler(method, start, end, handler):
    method.exception_status = 'PRESENT'
    method.exception_regions = [dict(start=start, end=end, handlers=[dict(address=40, type='*')])]
    method.instructions.extend(handler)
    for instruction in method.instructions:
        instruction.normal_successors = list(instruction.successors)


@pytest.mark.parametrize('fail_open', [False, True])
def test_helper_exception_return_distinguishes_fail_closed(helper_guarded, fail_open):
    add_handler(helper_guarded.methods[HELPER], 0, 14, [
        I(40, 'move-exception', [9], defs=[9], successors=[41]),
        I(41, 'const/4', [4], defs=[4], literal=int(fail_open), successors=[42]), I(42, 'return', [4])])
    report = url_guard_review(helper_guarded, CALLER, 3)
    assert report['host_allowlist'] == ('UNKNOWN' if fail_open else 'MODELED_EXACT_MATCH')
    assert report['exception_transitions'] > 0
    if not fail_open:
        assert report['status'] == 'EXCEPTION_FLOW_CONSTRAINED'


@pytest.mark.parametrize('bypass', [False, True])
def test_caller_exception_return_or_bypass(helper_guarded, bypass):
    last = I(41, 'goto', successors=[3]) if bypass else I(41, 'return-void')
    add_handler(helper_guarded.methods[CALLER], 0, 3,
                [I(40, 'move-exception', [9], defs=[9], successors=[41]), last])
    report = url_guard_review(helper_guarded, CALLER, 3)
    assert report['host_allowlist'] == ('UNKNOWN' if bypass else 'MODELED_EXACT_MATCH')


def test_multiple_handlers_one_bypass_is_unknown(helper_guarded):
    caller = helper_guarded.methods[CALLER]
    add_handler(caller, 0, 3, [I(40, 'return-void'), I(50, 'goto', successors=[3])])
    caller.exception_regions[0]['handlers'].append(dict(address=50, type='Ljava/lang/Exception;'))
    assert url_guard_review(helper_guarded, CALLER, 3)['host_allowlist'] == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['missing-handler', 'unaligned-end', 'overlap', 'missing-normal', 'handler-cycle'])
def test_invalid_or_cyclic_exception_cfg_is_unknown(helper_guarded, kind):
    caller = helper_guarded.methods[CALLER]
    add_handler(caller, 0, 3, [I(40, 'return-void')])
    if kind == 'missing-handler':
        caller.exception_regions[0]['handlers'][0]['address'] = 999
    elif kind == 'unaligned-end':
        caller.exception_regions[0]['end'] = 999
    elif kind == 'overlap':
        caller.exception_regions.append(dict(caller.exception_regions[0]))
    elif kind == 'missing-normal':
        caller.instructions[0].normal_successors = None
    else:
        caller.instructions[-1].opcode = 'goto'
        caller.instructions[-1].normal_successors = [0]
    assert url_guard_review(helper_guarded, CALLER, 3)['status'] == 'UNKNOWN'


def test_exception_metadata_roundtrip(helper_guarded, tmp_path):
    from analyzer.core.models import AnalysisResult
    from analyzer.app.project_manager import save_project, open_project
    add_handler(helper_guarded.methods[CALLER], 0, 3, [I(40, 'return-void')])
    path = tmp_path / 'exceptions.json'
    save_project(path, AnalysisResult('fixture.apk', 'fixture', program=helper_guarded))
    restored = open_project(path)
    assert url_guard_review(restored.program, CALLER, 3)['host_allowlist'] == 'MODELED_EXACT_MATCH'
