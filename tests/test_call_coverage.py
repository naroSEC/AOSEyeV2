from copy import deepcopy

import pytest

from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.project_manager import open_project, save_project
from analyzer.core.models import Program, Method, Instruction, AnalysisResult
from analyzer.core.call_coverage import call_coverage, coverage_text, STATUSES
from analyzer.gui.coverage import coverage_label


def fixture():
    names = {k: 'Ltest;->%s()V' % k for k in STATUSES}
    instructions = [Instruction(i, 'invoke-static', target=sig if kind != 'missing_operand' else '')
                    for i, (kind, sig) in enumerate(names.items())]
    caller = Method('Lcaller;->run()V', unit='caller', instructions=instructions)
    program = Program(methods={caller.signature: caller})
    for kind in ('body_available', 'ambiguous_units', 'unknown_origin'):
        sig = names[kind]
        program.methods[sig] = Method(sig, unit='' if kind == 'unknown_origin' else 'a')
    for kind, unit, code in [('body_available', 'a', True), ('ambiguous_units', 'b', True),
                             ('indexed_body_missing', 'a', True), ('declared_no_code', 'a', False),
                             ('declaration_unknown', 'a', None)]:
        program.method_index.append(dict(signature=names[kind], unit=unit, declared=True, has_code=code))
    # A reference from another unit is NOT a duplicate definition.
    program.method_index.append(dict(signature=names['body_available'], unit='reference-unit', declared=False))
    return program


def test_partition_and_nonmutation():
    program = fixture()
    before = deepcopy(program)
    value = call_coverage(program)
    assert value['counts'] == {k: 1 for k in STATUSES}
    assert value['invoke_sites'] == value['instructions_scanned'] == 8
    assert value['dynamic_dispatch_sites'] == 0
    assert program == before


def test_repeated_sites_dynamic_dispatch_and_no_inheritance_guess():
    base = Method('Lbase;->f()V', unit='u')
    caller = Method('Lc;->f()V', unit='u', instructions=[
        Instruction(0, 'invoke-virtual', target=base.signature),
        Instruction(1, 'invoke-interface', target=base.signature),
        Instruction(2, 'invoke-super', target='Lchild;->f()V'),
        Instruction(3, 'iget', target='Lchild;->f:I'),
        Instruction(4, 'invoke-custom', target='callsite@1')])
    value = call_coverage(Program(methods={base.signature: base, caller.signature: caller},
                                  class_hierarchy={'Lchild;': 'Lbase;'}))
    assert value['invoke_sites'] == 4 and value['dynamic_dispatch_sites'] == 3
    assert value['counts']['body_available'] == 2
    assert value['counts']['unindexed_target'] == value['counts']['missing_operand'] == 1


def test_duplicate_declaration_rows_and_unknown_origins():
    program = fixture()
    row = program.method_index[0]
    program.method_index.append(dict(row))
    assert call_coverage(program)['counts']['body_available'] == 1
    program.method_index.append(dict(row, unit=''))
    assert call_coverage(program)['counts']['unknown_origin'] == 2


def test_cancel_during_instruction_scan():
    class Token:
        calls = 0
        def check(self):
            self.calls += 1
            if self.calls == 3:
                raise Cancelled()
    method = Method('Lc;->f()V', instructions=[Instruction(i, 'nop') for i in range(1024)])
    with pytest.raises(Cancelled):
        call_coverage(Program(methods={method.signature: method}), Token())
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        call_coverage(Program(), token)


def test_save_reopen_and_legacy(tmp_path):
    result = AnalysisResult('fixture.apk', '0' * 64, program=fixture())
    assert 'Call-target coverage: not recorded.' in coverage_label(result)
    result.provenance['call_target_coverage'] = call_coverage(result.program)
    path = tmp_path / 'project.json'
    save_project(path, result)
    loaded = open_project(path)
    assert loaded.provenance == result.provenance
    assert coverage_label(loaded) == coverage_label(result)
    assert 'ambiguous units 1' in coverage_label(loaded)
    assert 'indexed_body_missing: 1' in coverage_text(loaded.provenance['call_target_coverage'], details=True)


@pytest.mark.parametrize('bad', [True, -1, 1.5, '1', 10**13])
def test_invalid_saved_counter(bad):
    value = call_coverage(fixture())
    value['counts']['body_available'] = bad
    assert 'invalid saved counters' in coverage_text(value)


def test_invalid_totals_and_empty():
    value = call_coverage(Program())
    assert 'call sites: 0' in coverage_text(value)
    value['invoke_sites'] = 1
    assert 'invalid saved counters' in coverage_text(value)
