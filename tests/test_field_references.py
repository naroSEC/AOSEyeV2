import json
import pytest
from analyzer.core.models import Program, Method, Instruction, AnalysisResult
from analyzer.core.field_references import field_references
from analyzer.app.jobs import Cancellation, Cancelled
from test_dex_browser import browser

FIELD = 'Lp/C;->value:I'
METHOD = 'Lp/C;->m()V'


def program(instructions, unit='a'):
    return Program(methods={METHOD: Method(METHOD, 'Lp/C;', instructions=instructions, unit=unit)},
                   field_index=[dict(signature=FIELD, unit=unit)])


@pytest.mark.parametrize('opcode,access', [(base + suffix, access)
    for base, access in [('iget', 'READ'), ('sget', 'READ'), ('iput', 'WRITE'), ('sput', 'WRITE')]
    for suffix in ('', '-wide', '-object', '-boolean', '-byte', '-char', '-short')])
def test_field_read_write_opcodes(opcode, access):
    p = program([Instruction(6, opcode, target=FIELD)])
    result, links = field_references(p, FIELD, 'a')
    assert result['items'][0]['access'] == access
    assert links[0]['offset'] == 6 and links[0]['unit'] == 'a'


def test_exact_operand_unit_and_unknown_origins():
    p = program([Instruction(0, 'sget', target=FIELD),
                 Instruction(2, 'sput', target=FIELD + 'different'),
                 Instruction(4, 'invoke-static', target=FIELD),
                 Instruction(6, 'iget-quick', target=FIELD)])
    result, links = field_references(p, FIELD, 'a')
    assert len(result['items']) == len(links) == 1
    assert field_references(p, FIELD, 'b')[0]['items'] == []
    result, links = field_references(p, FIELD, '')
    assert len(result['items']) == 1 and not links
    assert 'UNKNOWN' in result['scope'] and not result['items'][0]['navigation_allowed']


@pytest.mark.parametrize('offsets', [[-1], [True], [0, 0], [True, 1]])
def test_ambiguous_or_invalid_offsets_never_linked(offsets):
    p = program([Instruction(o, 'sget', target=FIELD) for o in offsets])
    result, links = field_references(p, FIELD, 'a')
    assert result['items'] and not links


def test_bounds_and_cancel_even_without_matches():
    p = program([Instruction(i * 2, 'sget', target=FIELD) for i in range(301)])
    result, links = field_references(p, FIELD, 'a')
    assert result['shown'] == 300 and result['truncated'] and len(links) == 300
    p.methods[METHOD].instructions.pop()
    assert not field_references(p, FIELD, 'a')[0]['truncated']
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        field_references(p, 'missing', 'a', cancel=token)
    with pytest.raises(ValueError):
        field_references(p, FIELD, limit=0)


def test_gui_field_links_history_and_no_finding_mutation(browser):
    w, wait = browser
    p = program([Instruction(0, 'sget', target=FIELD), Instruction(2, 'sput', target=FIELD)])
    result = AnalysisResult('test.apk', '0' * 64, program=p, notes={'old': 'keep'})
    w._loaded(result)
    w.openDexMethod(METHOD)
    origin = dict(w.evidenceLocation)
    w.openDexClass('Lp/C;')
    wait()
    index = next(i for i, row in enumerate(w.dexItems) if row['kind'] == 'field')
    w.openDexEntry(index)
    wait()
    assert w.currentTab == 'Field XREF' and len(w.navigationItems) == 2
    assert [r['access'] for r in json.loads(w.content)['items']] == ['READ', 'WRITE']
    link = w.navigationItems[1]
    w.navigateLocation(link['method'], link['offset'], link['unit'])
    assert '>>> 0002' in w.content
    w.goBack()
    assert w.evidenceLocation == origin
    w.showTab('Field XREF')
    wait()
    assert len(w.navigationItems) == 2
    assert result.notes == {'old': 'keep'} and not result.findings


@pytest.mark.parametrize('failure', ['cancel', 'stale'])
def test_gui_late_results_not_committed(browser, monkeypatch, failure):
    w, wait = browser
    w._loaded(AnalysisResult('test.apk', '0' * 64,
                            program=program([Instruction(0, 'sget', target=FIELD)])))
    w.openDexClass('Lp/C;')
    wait()
    def start(work, finish):
        w._busy = True
        w._finish_callback = finish
        value = work(None)
        if failure == 'cancel':
            w.cancel_token.cancel()
        else:
            w._field_selection = None
        w._success(value)
    monkeypatch.setattr(w, '_start', start)
    w.openDexEntry(1)
    assert not w.busy and not w.navigationItems
    assert 'cancel' in w.stage.lower() or 'Stale' in w.stage
