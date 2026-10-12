import pytest
from analyzer.core.graph import DeclarationResolver, reference_query, verify_native_xref
from analyzer.core.models import Program, Method, Instruction
from analyzer.analyzers.manifest import entry_catalog
from analyzer.analyzers.verification import CandidateReviewer
from analyzer.core.dataflow import FlowEngine
from analyzer.core.rules.registry import RuleRegistry
from analyzer.app.jobs import Cancellation
from analyzer.backends.jeb.backend import JebBackend
from analyzer.app.settings import Settings
from conftest import ENTRY, HELPER


CHILD = 'Ltest/Child;->onCreate(Landroid/os/Bundle;)V'
BASE = 'Ltest/Base;->onCreate(Landroid/os/Bundle;)V'


@pytest.mark.parametrize('metadata,status', [
    ({'declared': True, 'has_code': False}, 'DECLARED_NO_BODY'),
    ({'declared': True, 'has_code': True}, 'DECLARED_NO_BODY'),
    ({'has_code': False}, 'UNKNOWN_DECLARATION'),
    ({'declared': None}, 'UNKNOWN_DECLARATION'),
])
def test_lifecycle_reviewer_backend_share_override_barrier(metadata, status):
    caller = Method('Ltest/Caller;->call()V', instructions=[Instruction(0, 'invoke-virtual', target=CHILD)])
    program = Program(methods={BASE: Method(BASE), caller.signature: caller},
                      class_hierarchy={'Ltest/Child;': 'Ltest/Base;'},
                      method_index=[dict(signature=CHILD, **metadata)])
    manifest = {'components': [dict(name='test.Child', target='test.Child', kind='activity',
                                    exported=True, enabled=True, permission='')]}
    resolver = DeclarationResolver(program)
    assert resolver.resolve(CHILD) == (CHILD, status)
    catalog = entry_catalog(manifest, program.methods, program.class_hierarchy, program.method_index)
    assert not catalog['confirmed'] and not catalog['uncertain']
    assert catalog['records'][0]['resolution'] == status and catalog['diagnostics']
    reviewer = CandidateReviewer(program, manifest)
    assert not reviewer.reverse and not reviewer.entries
    backend = JebBackend(Settings())
    backend.program = program
    assert backend.get_callers(BASE) == [] and backend.get_callees(caller.signature) == [CHILD]
    assert not backend.get_xrefs(BASE)
    edge = reference_query(program, CHILD)['edges'][0]
    assert edge['callee'] == CHILD and edge['resolution'] == status
    checked = verify_native_xref(program, BASE, {'address': caller.signature + '+0h'})
    assert checked['target_validation'] != 'INHERITED_DECLARATION'


@pytest.mark.parametrize('declared', [True, None])
def test_flow_does_not_cross_bodyless_override(flow_program, declared):
    raw = HELPER.replace('Nav', 'Child')
    flow_program.class_hierarchy = {'Ltest/Child;': 'Ltest/Nav;'}
    flow_program.methods[ENTRY].instructions[-2].target = raw
    flow_program.method_index = [dict(signature=raw, declared=declared, has_code=False)]
    findings, diagnostics = FlowEngine(RuleRegistry()).analyze(flow_program, {ENTRY}, Cancellation())
    assert not findings
    assert any(('no indexed body' if declared else 'reindex required') in d for d in diagnostics)


def test_reference_only_inherits_and_indexed_override_wins():
    program = Program(methods={BASE: Method(BASE)}, class_hierarchy={'Ltest/Child;': 'Ltest/Base;'},
                      method_index=[dict(signature=CHILD, declared=False)])
    assert DeclarationResolver(program).resolve(CHILD) == (BASE, 'INHERITED_DECLARATION')
    program.methods[CHILD] = Method(CHILD)
    assert DeclarationResolver(program).resolve(CHILD) == (CHILD, 'EXACT')


def test_cycle_and_constructors_do_not_invent_inheritance():
    program = Program(class_hierarchy={'Ltest/Child;': 'Ltest/Child;'})
    resolver = DeclarationResolver(program)
    assert resolver.resolve(CHILD) == (CHILD, 'HIERARCHY_CYCLE')
    assert any('cycle' in d for d in resolver.diagnostics)
    child_init, base_init = 'Ltest/Child;-><init>()V', 'Ltest/Base;-><init>()V'
    program = Program(methods={base_init: Method(base_init)}, class_hierarchy={'Ltest/Child;': 'Ltest/Base;'})
    assert DeclarationResolver(program).resolve(child_init) == (child_init, 'UNINDEXED_REFERENCE')


def test_resolver_snapshot_refreshes_between_queries():
    program = Program(methods={BASE: Method(BASE)}, class_hierarchy={'Ltest/Child;': 'Ltest/Base;'})
    assert DeclarationResolver(program).target(CHILD) == BASE
    program.method_index.append(dict(signature=CHILD, declared=True))
    assert DeclarationResolver(program).resolve(CHILD) == (CHILD, 'DECLARED_NO_BODY')
