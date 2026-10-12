import pytest
from analyzer.core.models import Instruction, Method, Program
from analyzer.core.graph import reference_query
from analyzer.core.navigation import bytecode_location, reference_links
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.project_manager import save_project, open_project
from analyzer.core.models import AnalysisResult
from conftest import ENTRY, HELPER


def test_inherited_calls_keep_raw_operand_and_share_backend_resolution(flow_program):
    from analyzer.backends.jeb.backend import JebBackend
    from analyzer.app.settings import Settings
    from analyzer.analyzers.verification import CandidateReviewer
    raw = HELPER.replace('Nav', 'Child')
    flow_program.class_hierarchy['Ltest/Child;'] = 'Ltest/Nav;'
    flow_program.methods[ENTRY].instructions[-2].target = raw
    backend = JebBackend(Settings())
    backend.program = flow_program
    edge = next(e for e in reference_query(flow_program, HELPER)['edges'] if e['offset'] == 20)
    assert edge['raw_declared_target'] == raw and edge['callee'] == HELPER
    assert edge['resolution'] == 'INHERITED_DECLARATION'
    assert ENTRY in backend.get_callers(HELPER)
    assert HELPER in backend.get_callees(ENTRY)
    assert backend.get_xrefs(HELPER)[0]['raw_declared_target'] == raw
    assert CandidateReviewer(flow_program, {}).reverse[HELPER][0]['caller'] == ENTRY


def test_query_limits_incoming_and_cancellation(flow_program):
    query = reference_query(flow_program, ENTRY, limit=1)
    assert query['truncated'] and len(query['edges']) == 1
    query = reference_query(flow_program, HELPER, incoming_only=True)
    assert len(query['edges']) == 1 and query['edges'][0]['caller'] == ENTRY
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        reference_query(flow_program, 'missing', cancel=token)
    with pytest.raises(ValueError):
        reference_query(flow_program, limit=0)


@pytest.mark.parametrize('method,offset,unit', [(ENTRY, 21, ''), ('missing', 0, ''),
                                             (ENTRY, -1, ''), (ENTRY, 20, 'wrong-unit')])
def test_bad_location_rejected(flow_program, method, offset, unit):
    with pytest.raises(ValueError):
        bytecode_location(flow_program, method, offset, unit)


def test_exact_location_roundtrip_and_links(flow_program, tmp_path):
    flow_program.methods[ENTRY].unit = 'dex-1'
    flow_program.methods[HELPER].unit = 'dex-2'
    path = tmp_path / 'project.json'
    save_project(path, AnalysisResult('app.apk', 'abc', program=flow_program))
    program = open_project(path).program
    location, text = bytecode_location(program, ENTRY, 20, 'dex-1')
    assert location == dict(method=ENTRY, offset=20, unit='dex-1')
    assert '>>> 0014' in text and 'No source-line mapping' in text
    links = reference_links(program, reference_query(program, HELPER, incoming_only=True)['edges'])
    assert links == [dict(label='Call site', method=ENTRY, offset=20, unit='dex-1'),
                     dict(label='Declared target', method=HELPER, offset=0, unit='dex-2')]


def test_bytecode_window_is_bounded():
    program = Program(methods={'m': Method('m', instructions=[Instruction(i, 'nop') for i in range(10000)])})
    _, text = bytecode_location(program, 'm', 5000)
    assert len(text.splitlines()) < 70
    assert '>>> 1388' in text
