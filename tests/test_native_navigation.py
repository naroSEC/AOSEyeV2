import pytest
from analyzer.core.navigation import native_reference_page
from analyzer.app.jobs import Cancellation, Cancelled
from conftest import ENTRY, HELPER


def page(items, total=None):
    return dict(items=items, total=len(items) if total is None else total, offset=0,
                evidence_origin='JEB getCrossReferences')


def test_native_links_are_reverified_deduplicated_and_raw_preserved(flow_program):
    flow_program.methods[ENTRY].unit = 'dex-1'
    raw = dict(address=ENTRY + '+14h', unit='dex-1', reference_type='INVOKE',
               target_validation='DIFFERENT_DECLARED_TARGET')
    result, links = native_reference_page(flow_program, HELPER, page([raw, raw], total=5))
    assert len(links) == 1 and links[0]['offset'] == 20
    assert links[0]['unit'] == 'dex-1'
    assert result['has_more'] and result['shown'] == 2
    assert result['items'][0]['navigation_allowed'] is True
    assert result['items'][0]['address'] == raw['address']
    assert raw['target_validation'] == 'DIFFERENT_DECLARED_TARGET'
    assert 'navigation_allowed' not in raw


@pytest.mark.parametrize('changes', [dict(unit='wrong'), dict(unit=''), dict(address=ENTRY + '+15h'),
    dict(address=ENTRY), dict(address=None), dict(address='Lmissing;->m()V+14h'),
    dict(address=ENTRY + '+' + 'f' * 100 + 'h')])
def test_bad_native_locations_not_linked(flow_program, changes):
    flow_program.methods[ENTRY].unit = 'dex-1'
    raw = dict(address=ENTRY + '+14h', unit='dex-1', target_validation='EXACT_DECLARED_TARGET',
               caller=ENTRY, offset=20)
    raw.update(changes)
    result, links = native_reference_page(flow_program, HELPER, page([raw]))
    assert not links and not result['items'][0]['navigation_allowed']


def test_other_target_not_linked_even_with_forged_validation(flow_program):
    flow_program.methods[ENTRY].unit = 'dex-1'
    raw = dict(address=ENTRY + '+14h', unit='dex-1', target_validation='EXACT_DECLARED_TARGET')
    result, links = native_reference_page(flow_program, 'Lother;->m()V', page([raw]))
    assert not links and result['items'][0]['target_validation'] == 'DIFFERENT_DECLARED_TARGET'


def test_inherited_native_target_link_and_legacy_barrier(flow_program):
    flow_program.methods[ENTRY].unit = 'dex-1'
    child = HELPER.replace('Nav', 'Child')
    flow_program.methods[ENTRY].instructions[-2].target = child
    flow_program.class_hierarchy = {'Ltest/Child;': 'Ltest/Nav;'}
    raw = dict(address=ENTRY + '+14h', unit='dex-1')
    result, links = native_reference_page(flow_program, HELPER, page([raw]))
    assert links and result['items'][0]['target_validation'] == 'INHERITED_DECLARATION'
    flow_program.method_index = [dict(signature=child)]
    result, links = native_reference_page(flow_program, HELPER, page([raw]))
    assert not links and result['items'][0]['target_validation'] == 'UNVERIFIED'


def test_unknown_normalized_unit_not_linked(flow_program):
    result, links = native_reference_page(flow_program, HELPER, page([dict(address=ENTRY + '+14h', unit='dex-1')]))
    assert not links and not result['items'][0]['navigation_allowed']


def test_native_page_cancelled(flow_program):
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        native_reference_page(flow_program, HELPER, page([dict(address=ENTRY + '+14h')]), token)
