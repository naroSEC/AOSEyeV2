import json
import pytest
from analyzer.core.field_references import field_references
from analyzer.core.models import Instruction
from analyzer.gui.field_view import field_page_text
from test_field_references import program, FIELD, METHOD


class CountingInstructions(list):
    iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


@pytest.mark.parametrize('unit,target,offset,expected', [
    ('', FIELD, 0, 1), ('a', 'unmatched', 0, 1),
    ('a', FIELD, 0, 2), ('a', FIELD, 300, 1)])
def test_only_linkable_page_candidates_build_offset_index(unit, target, offset, expected):
    instructions = CountingInstructions([Instruction(i * 2, 'sget', target=FIELD) for i in range(300)])
    p = program(instructions)
    p.methods[METHOD].instructions = instructions
    field_references(p, target, unit, offset=offset)
    assert instructions.iterations == expected


@pytest.mark.parametrize('count', [0, 1, 300])
def test_compact_field_text_preserves_complete_json(count):
    p = program([Instruction(i * 2, 'sget', target=FIELD) for i in range(count)])
    page, _ = field_references(p, FIELD, 'a')
    page['extra_unicode'] = '\ud800😀'
    text = field_page_text(page)
    assert json.loads(text) == page
    assert text.count('\n') < count + 30
