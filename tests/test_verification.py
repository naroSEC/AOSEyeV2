from analyzer.analyzers.verification import CandidateReviewer
from analyzer.core.models import Program, Finding, Location, Instruction as I
from conftest import method, ENTRY, HELPER


def manifest():
    return {'components': [dict(name='test.Main', target='test.Main', kind='activity', exported=True,
                                enabled=True, permission='', attributes={})]}


def test_declared_path_is_not_a_taint_or_validation_proof(flow_program):
    f = Finding('test', 'test', '', 'WEBVIEW', location=Location(method=HELPER, offset=0),
                validation={'host_allowlist': 'UNKNOWN'})
    CandidateReviewer(flow_program, manifest()).annotate(f)
    assert f.review['reachability']['status'] == 'DECLARED_PATH_FOUND'
    assert f.review['reachability']['paths'][0]['edges'][0]['offset'] == 20
    assert f.validation['host_allowlist'] == 'UNKNOWN'
    assert f.verification == 'MANUAL_REVIEW'


def test_absence_of_graph_path_is_not_proof_of_dead_code(flow_program):
    flow_program.methods[ENTRY].instructions[5].target = 'Lunknown/Loader;->invoke()V'
    r = CandidateReviewer(flow_program, manifest()).reachability(HELPER)
    assert r['status'] == 'NO_MODELED_PATH_FOUND' and not r['truncated']
    assert 'proof of dead code' in r['scope']


def test_search_budget_cannot_report_no_path(flow_program):
    r = CandidateReviewer(flow_program, manifest()).reachability(HELPER, max_nodes=1)
    assert r['status'] == 'INCOMPLETE' and r['truncated']


def test_permission_protected_entry_not_unprotected_root(flow_program):
    m = manifest(); m['components'][0]['permission'] = 'test.SIGNATURE'
    assert CandidateReviewer(flow_program, m).reachability(HELPER)['status'] == 'NO_MODELED_PATH_FOUND'


def test_unknown_entry_is_a_possible_not_confirmed_graph_root(flow_program):
    m = manifest(); m['components'][0]['enabled'] = None
    reviewer = CandidateReviewer(flow_program, m)
    assert not reviewer.entries and reviewer.uncertain_entries == {ENTRY}
    assert reviewer.reachability(HELPER)['status'] == 'POSSIBLE_ENTRY_PATH_FOUND'


def test_guard_that_merges_before_sink_is_not_a_sanitizer():
    sig = 'Ltest/C;->f()V'
    m = method(sig, [I(0, 'invoke-virtual', [1, 2], target='Ljava/lang/String;->startsWith(Ljava/lang/String;)Z'),
        I(6, 'move-result', [0], defs=[0]), I(8, 'if-eqz', [0], successors=[10, 12]),
        I(10, 'goto', successors=[14]), I(12, 'goto', successors=[14]), I(14, 'return-void')])
    r = CandidateReviewer(Program(methods={sig:m}), {}).guard_context(sig, 14)
    branch = r['branches'][0]
    assert branch['dominates_observation']
    assert branch['classification'] == 'BOTH_SUCCESSORS_REACH'
    assert branch['predicate_call']['offset'] == 0
    assert r['status'] == 'STRUCTURAL_ONLY'


def test_guard_single_accepting_edge_still_has_unknown_semantics():
    sig = 'Ltest/C;->f()V'
    m = method(sig, [I(0,'if-eqz',[0],successors=[2,4]),I(2,'return-void'),I(4,'return-void')])
    r = CandidateReviewer(Program(methods={sig:m}), {}).guard_context(sig, 4)
    assert r['branches'][0]['classification'] == 'ONE_SUCCESSOR_REACHES'
    assert 'predicate meaning' in r['caveat']


def test_bypass_branch_is_not_dominating():
    sig='Ltest/C;->f()V'
    m=method(sig,[I(0,'if-eqz',[0],successors=[2,6]),I(2,'if-eqz',[1],successors=[4,6]),
                  I(4,'return-void'),I(6,'return-void')])
    r=CandidateReviewer(Program(methods={sig:m}),{}).guard_context(sig,6)
    assert not next(b for b in r['branches'] if b['offset']==2)['dominates_observation']


def test_unresolved_cfg_is_limited_not_proven():
    sig='Ltest/C;->f()V'
    m=method(sig,[I(0,'if-eqz',[0],successors=[2,999]),I(2,'return-void')])
    assert CandidateReviewer(Program(methods={sig:m}),{}).guard_context(sig,2)['status']=='LIMITED'


def test_native_xref_other_declaration_is_not_a_caller(flow_program):
    from analyzer.core.graph import verify_native_xref
    raw = dict(address=ENTRY + '+14h', reference_type='INVOKE')
    assert verify_native_xref(flow_program, HELPER, raw)['target_validation'] == 'EXACT_DECLARED_TARGET'
    other = 'Ltest/Other;->onCreate(Landroid/os/Bundle;)V'
    checked = verify_native_xref(flow_program, other, raw)
    assert checked['target_validation'] == 'DIFFERENT_DECLARED_TARGET'
    assert checked['raw_declared_target'] == HELPER
    assert 'target_validation' not in raw


def test_unparseable_native_xref_remains_unverified(flow_program):
    from analyzer.core.graph import verify_native_xref
    assert verify_native_xref(flow_program, HELPER, {'address': ENTRY})['target_validation']=='UNVERIFIED'


def test_unreachable_guard_is_not_reported():
    sig='Ltest/C;->f()V'
    m=method(sig,[I(0,'goto',successors=[4]),I(2,'if-eqz',[0],successors=[4,6]),
                  I(4,'return-void'),I(6,'return-void')])
    assert not CandidateReviewer(Program(methods={sig:m}),{}).guard_context(sig,4)['branches']
