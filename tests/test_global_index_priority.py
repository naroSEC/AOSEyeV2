"""Execute the production bridge index function against deterministic multi-unit doubles."""
import ast
import importlib.util
import json
from io import StringIO
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from test_index_priority import module, item


def test_global_stable_origins_and_late_priority():
    groups = [[item('Lsdk/A;'), item('Lapp/A;')],
              [item('Lentry/Main;'), item('Lapp/A;')]]
    selected = module.select_global(groups, 3, ['Lentry/Main;'], 'Lapp/')
    assert selected == [(1, groups[1][0]), (0, groups[0][1]), (1, groups[1][1])]
    assert module.select_global(groups, 0, [], '') == []
    assert module.select_global(groups, 2, [], '') == [(0, x) for x in groups[0]]


def bridge_index():
    folder = Path(__file__).resolve().parents[1] / 'src/analyzer/backends/jeb/scripts'
    tree = ast.parse((folder / 'AOSEyeBridge.py').read_text(encoding='utf-8'))
    function = next(n for cls in tree.body if isinstance(cls, ast.ClassDef)
                    for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'index')
    spec = importlib.util.spec_from_file_location('test_export_budget_global', folder / 'ExportBudget.py')
    budget = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(budget)
    scope = dict(ExportBudget=budget.ExportBudget, select_global=module.select_global,
                 IApkUnit=object, JavaException=Exception)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(folder / 'AOSEyeBridge.py'), 'exec'), scope)
    return scope['index']


def unit(name, signature):
    cls = item(signature)
    cls.getSupertypeSignature = lambda _: None
    cls.getInterfaceSignatures = lambda _: []
    method = item(signature + '->run()V')
    method.getData = lambda: NS(getCodeItem=lambda: object())
    return NS(getName=lambda: name, getCountOfDexEntries=lambda: 1,
              getClasses=lambda: [cls], getFields=lambda: [item(signature + '->f:I')],
              getMethods=lambda: [method])


@pytest.mark.parametrize('order,expected', [('native', '0:first'), ('manifest-first', '1:last')])
@pytest.mark.parametrize('byte_limit', [1, 400, 10000])
def test_bridge_global_budget_origin_and_counts(order, expected, byte_limit):
    units = [unit('first', 'Lsdk/A;'), unit('last', 'Lentry/Main;')]
    ctx = NS(project=NS(findUnit=lambda _: None), capabilities={})
    bridge = NS(unit_id=lambda n, dex: str(n) + ':' + dex.getName())
    def normalize(dex, method):
        assert method in dex.getMethods()
        return dict(signature=method.getSignature(False))
    bridge.method = normalize
    stream = StringIO()
    result = bridge_index()(bridge, ctx, units, dict(index_order=order,
        max_index_entries=1, max_index_bytes=byte_limit, priority_classes=['Lentry/Main;']), stream)
    bodies = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert len(bodies) == len(result['method_index'])
    assert all(body['unit'] == expected for body in bodies)
    assert len(result['dex_units']) == 2
    for plural, key in [('classes', 'class_index'), ('fields', 'field_index'), ('methods', 'method_index')]:
        rows = result[key]
        assert len(rows) <= 1
        assert all(row['unit'] == expected for row in rows)
        assert 'omitted_%s=%d' % (plural, 2 - len(rows)) in result['diagnostics'][0]
    if byte_limit == 1:
        assert not result['class_index']
    else:
        assert result['class_index'][0]['unit'] == expected


def test_saved_global_and_legacy_scope():
    from analyzer.core.models import AnalysisResult
    from analyzer.gui.coverage import index_policy_label
    result = AnalysisResult('fixture.apk', '0' * 64)
    result.provenance['requested_index_order'] = 'manifest-first'
    for scope, expected in [('within each JEB unit', 'within each JEB unit only'),
                            ('global across JEB units', 'Global priority across JEB units')]:
        result.program.capabilities['index_order'] = 'manifest-first (%s; not ownership/entrypoint proof)' % scope
        assert expected in index_policy_label(result)


@pytest.mark.parametrize('order', ['native', 'manifest-first'])
def test_large_field_inventory_cannot_starve_method_declarations(order):
    dex = unit('test', 'Lapp/Main;')
    dex.getFields = lambda: [item('Lapp/Main;->field%d:I' % n) for n in range(1000)]
    ctx = NS(project=NS(findUnit=lambda _: None), capabilities={})
    bridge = NS(unit_id=lambda n, dex: '0:test',
                method=lambda dex, method: dict(signature=method.getSignature(False)))
    stream = StringIO()
    result = bridge_index()(bridge, ctx, [dex], dict(index_order=order,
        max_index_entries=2000, max_index_bytes=4096), stream)
    assert len(result['method_index']) == 1 and stream.getvalue()
    assert len(result['field_index']) < 1000
    assert any('omitted_fields=' in d for d in result['diagnostics'])
    assert 'half' in ctx.capabilities['declaration_budget']
