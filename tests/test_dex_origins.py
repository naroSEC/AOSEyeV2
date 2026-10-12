import pytest
from analyzer.core.models import Program, Method, Instruction, AnalysisResult
from analyzer.gui.dex_browser import dex_page
from analyzer.app.project_manager import save_project, open_project
from test_dex_browser import browser


def sample():
    sig = 'Lp/C;->m()V'
    return Program(methods={sig: Method(sig, 'Lp/C;', [0], [Instruction(0, 'return-void')], unit='a')},
        classes=['Lp/C;', 'Llegacy;'], fields=['Lp/C;->value:I', 'Llegacy;->unknown:I'],
        dex_units=[dict(id='a'), dict(id='b')],
        class_index=[dict(signature='Lp/C;', unit=u) for u in ('a', 'b')],
        field_index=[dict(signature='Lp/C;->value:I', unit=u) for u in ('a', 'b')],
        method_index=[dict(signature=sig, unit=u, declared=True, has_code=True) for u in ('a', 'b')])


def test_unit_package_class_and_field_origins():
    p = sample()
    assert [r['unit'] for r in dex_page(p, mode='units')['items']] == ['a', 'b', '']
    assert dex_page(p, mode='packages', unit='b')['items'][0]['name'] == 'p'
    rows = dex_page(p, package='p')['items']
    assert len(rows) == 2 and all(r['duplicate'] for r in rows)
    a = dex_page(p, 'Lp/C;', unit='a')['items']
    b = dex_page(p, 'Lp/C;', unit='b')['items']
    assert [r['kind'] for r in a] == ['method', 'field']
    assert a[0]['has_body'] and not b[0]['has_body']
    assert all(r['unit'] == 'b' for r in b)
    legacy = dex_page(p, 'Llegacy;')['items']
    assert legacy[0]['unit'] == '' and legacy[0]['kind'] == 'field'
    assert dex_page(p, 'Llegacy;', unit='a')['items'] == []


def test_origin_round_trip_and_legacy_defaults(tmp_path):
    p = sample()
    path = tmp_path / 'origins.json'
    save_project(path, AnalysisResult('test.apk', '0' * 64, program=p))
    result = open_project(path)
    assert result.program.class_index == p.class_index
    assert result.program.field_index == p.field_index
    assert dex_page(result.program) == dex_page(p)
    assert Program.from_dict({}).class_index == []
    assert Program.from_dict({}).field_index == []


def test_unit_scoped_navigation_never_substitutes_another_body(browser):
    w, wait = browser
    w._loaded(AnalysisResult('test.apk', '0' * 64, program=sample()))
    w.dexBrowse('units')
    wait()
    w.openDexEntry(1)  # unit b
    wait()
    w.openDexEntry(0)  # package p
    wait()
    w.openDexEntry(0)  # class C
    wait()
    assert w._dex_page['unit'] == 'b'
    w.searchDex('m()')
    wait()
    w.openDexEntry(0)
    assert not w.evidenceLocation and 'not be substituted' in w.stage
    w.searchDex('value')
    wait()
    w.openDexEntry(0)
    wait()
    assert w.currentTab == 'Field XREF' and '"unit": "b"' in w.content
    assert w._selected is None
    w.dexBrowse('units')
    wait()
    w.openDexEntry(0)
    wait()
    w.openDexEntry(0)
    wait()
    w.openDexEntry(0)
    wait()
    w.openDexEntry(0)
    assert w.evidenceLocation['unit'] == 'a'


def test_scoped_member_pagination():
    p = sample()
    p.field_index.extend(dict(signature=f'Lp/C;->f{i}:I', unit='b') for i in range(601))
    page = dex_page(p, 'Lp/C;', unit='b', offset=600)
    assert page['total'] == 603 and len(page['items']) == 3 and not page['has_more']
    assert all(r['unit'] == 'b' for r in page['items'])
