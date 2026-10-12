import copy
import pytest
import yaml

from analyzer.core.rules.registry import RuleRegistry
from analyzer.core.rules.conditions import evaluate
from analyzer.core.dataflow import FlowEngine, Trace
from analyzer.core.models import Instruction as I
from analyzer.app.jobs import Cancellation
from conftest import ENTRY, HELPER, SOURCE


def load(tmp_path, data):
    path = tmp_path / 'rules.yaml'
    path.write_text(yaml.safe_dump(data), encoding='utf-8')
    return RuleRegistry(path)


@pytest.mark.parametrize('bad', [None, [], {'sources': [], 'transfers': [], 'sinks': [], 'typo': True}])
def test_invalid_root(tmp_path, bad):
    with pytest.raises(ValueError):
        load(tmp_path, bad)


@pytest.mark.parametrize('field,value', [('arguments', [True]), ('arguments', [256]), ('arguments', [1, 1]),
    ('arguments', '1'), ('signatures', []), ('signatures', ['']), ('category', 'BOGUS'),
    ('severity', 'fatal'), ('id', []), ('title', ''), ('cwe', ['CWE-abc']), ('cwe', 'CWE-20'),
    ('required_conditions', [{'kind': 'eval', 'code': 'never'}]),
    ('required_conditions', [{'kind': 'argument_constant', 'argument': True, 'equals': 1}]),
    ('required_conditions', [{'kind': 'argument_constant', 'argument': 1, 'equals': []}]),
    ('required_conditions', [{'kind': 'source_prefix', 'prefix': ''}]), ('typo', 1)])
def test_invalid_sink(tmp_path, field, value):
    data = copy.deepcopy(RuleRegistry().config)
    data['sinks'][0][field] = value
    with pytest.raises(ValueError):
        load(tmp_path, data)


@pytest.mark.parametrize('text', ['sources: []\nsources: []\ntransfers: []\nsinks: []',
    'sources: &a []\ntransfers: *a\nsinks: []', '[' * 40 + ']' * 40,
    'x' * (256 * 1024 + 1)], ids=['duplicate', 'alias', 'depth', 'bytes'])
def test_yaml_limits(tmp_path, text):
    path = tmp_path / 'bad.yaml'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(ValueError):
        RuleRegistry(path)


@pytest.mark.parametrize('constant,expected', [(1, 'MET'), (0, 'NOT_MET'), ('1', 'NOT_MET'), (None, 'UNKNOWN')])
def test_constant_condition(constant, expected):
    constants = {} if constant is None else {4: constant}
    assert evaluate([{'kind': 'argument_constant', 'argument': 0, 'equals': 1}], [4], constants,
                    Trace(SOURCE, ())) == expected


@pytest.mark.parametrize('source,expected', [(SOURCE, 'MET'), ('Lother;->read()V', 'NOT_MET'),
    ('external callback argument', 'UNKNOWN')])
def test_source_condition(source, expected):
    assert evaluate([{'kind': 'source_prefix', 'prefix': SOURCE}], [], {}, Trace(source, ())) == expected


@pytest.mark.parametrize('value,expected', [(3, 'MET'), (7, 'MET'), (2, 'NOT_MET'),
    (-1, 'MET'), (None, 'UNKNOWN'), (True, 'UNKNOWN'), ('3', 'UNKNOWN'), (2**40, 'UNKNOWN')])
def test_flag_condition(value, expected):
    condition = {'kind': 'argument_bits', 'argument': 1, 'mask': 3, 'equals': 3}
    assert evaluate([condition], [7, 8], {8: value}, Trace(SOURCE, ())) == expected


@pytest.mark.parametrize('mask,equals', [(0, 0), (-1, 0), (True, 1), (2**32, 0), (3, 4), (3, True)])
def test_invalid_flag_schema(tmp_path, mask, equals):
    data = copy.deepcopy(RuleRegistry().config)
    data['sinks'][0]['required_conditions'] = [dict(kind='argument_bits', argument=1, mask=mask, equals=equals)]
    with pytest.raises(ValueError): load(tmp_path, data)


@pytest.mark.parametrize('mode', ['met', 'not_met', 'unknown'])
@pytest.mark.parametrize('kind', ['argument_constant', 'argument_bits'])
def test_condition_integrates_with_flow_and_fingerprint(tmp_path, flow_program, mode, kind):
    baseline = RuleRegistry()
    data = copy.deepcopy(baseline.config)
    condition = {'kind': kind, 'argument': 0, 'equals': 7}
    if kind == 'argument_bits':
        condition['mask'] = 7
    data['sinks'][0]['required_conditions'] = [condition]
    rules = load(tmp_path, data)
    assert rules.fingerprint != baseline.fingerprint
    if mode != 'unknown':
        helper = flow_program.methods[HELPER]
        for ins in helper.instructions:
            ins.offset += 2
            ins.successors = [offset + 2 for offset in ins.successors]
        helper.instructions.insert(0, I(0, 'const/4', [1], defs=[1], literal=7 if mode == 'met' else 3, successors=[2]))
    findings, _ = FlowEngine(rules).analyze(flow_program, {ENTRY}, Cancellation())
    if mode == 'not_met':
        assert not findings
    else:
        f, = findings
        assert f.validation['required_conditions'] == ('MET' if mode == 'met' else 'UNKNOWN')
        if mode == 'unknown':
            assert f.type == 'REVIEW' and f.verification == 'MANUAL_REVIEW' and not f.attack_path
