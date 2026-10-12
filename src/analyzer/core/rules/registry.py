from pathlib import Path
from hashlib import sha256
import json
from typing import Protocol
import yaml
from analyzer.core.models import Finding, Program, Category, Severity


class RuleLoader(yaml.SafeLoader):
    """Small declarative documents only; aliases/duplicate keys are errors."""
    def __init__(self, stream):
        super().__init__(stream)
        self.depth = self.nodes = 0

    def compose_node(self, parent, index):
        self.nodes += 1
        if self.check_event(yaml.AliasEvent) or self.depth >= 32 or self.nodes > 20000:
            raise ValueError('Rule YAML alias or nesting/node budget exceeded')
        self.depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if type(key) is not str or key in result:
                raise ValueError('Rule YAML keys must be unique strings')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _arguments(value):
    return (type(value) is list and bool(value) and
            all(type(n) is int and 0 <= n <= 255 for n in value) and len(set(value)) == len(value))


def _signatures(value, exact=False):
    return (type(value) is list and bool(value) and
            all(type(s) is str and s.startswith('L') and ';->' in s and '(' in s
                and (not exact or ')' in s) for s in value) and len(set(value)) == len(value))


def _conditions(value):
    if type(value) is not list or len(value) > 16:
        return False
    for condition in value:
        if type(condition) is not dict:
            return False
        if condition.get('kind') == 'argument_constant':
            if (set(condition) != {'kind', 'argument', 'equals'} or
                    type(condition['argument']) is not int or not 0 <= condition['argument'] <= 255 or
                    type(condition['equals']) not in (str, int)):
                return False
        elif condition.get('kind') == 'source_prefix':
            if set(condition) != {'kind', 'prefix'} or not _signatures([condition['prefix']]):
                return False
        elif condition.get('kind') == 'argument_bits':
            if (set(condition) != {'kind', 'argument', 'mask', 'equals'} or
                    type(condition['argument']) is not int or not 0 <= condition['argument'] <= 255 or
                    type(condition['mask']) is not int or not 1 <= condition['mask'] <= 0xffffffff or
                    type(condition['equals']) is not int or not 0 <= condition['equals'] <= 0xffffffff or
                    condition['equals'] & ~condition['mask']):
                return False
        else:
            return False
    return True


class ProgrammaticRule(Protocol):
    def analyze(self, program: Program) -> list[Finding]: ...


class RuleRegistry:
    def __init__(self, path: Path | None = None):
        with (path or Path(__file__).with_name('flows.yaml')).open('rb') as stream:
            raw = stream.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise ValueError('Rule YAML byte budget exceeded')
        try:
            self.config = yaml.load(raw.decode('utf-8-sig'), Loader=RuleLoader)
        except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
            raise ValueError('Invalid rule YAML') from exc
        if (type(self.config) is not dict or set(self.config) != {'sources', 'transfers', 'sinks'} or
                not all(type(self.config[k]) is list for k in ('sources', 'transfers', 'sinks'))):
            raise ValueError('Invalid flow rule schema')
        if self.config['sources'] and not _signatures(self.config['sources']):
            raise ValueError('Invalid source rule')
        ids = set()
        transfer_signatures = set()
        for transfer in self.config['transfers']:
            if (type(transfer) is not dict or set(transfer) - {'signatures', 'arguments', 'uncertain'}
                    or not _signatures(transfer.get('signatures'), exact=True)
                    or not _arguments(transfer.get('arguments'))
                    or ('uncertain' in transfer and type(transfer['uncertain']) is not bool)):
                raise ValueError('Invalid transfer rule: explicit signatures and argument indices required')
            for signature in transfer['signatures']:
                if signature in transfer_signatures:
                    raise ValueError('Duplicate transfer signature')
                transfer_signatures.add(signature)
        for sink in self.config['sinks']:
            required = {'id', 'title', 'category', 'signatures', 'arguments', 'severity'}
            if (type(sink) is not dict or not required <= set(sink) or
                    set(sink) - required - {'cwe', 'required_conditions'} or
                    any(type(sink.get(k)) is not str or not sink[k].strip() for k in ('id', 'title')) or
                    sink['id'] in ids or not _arguments(sink['arguments']) or
                    not _signatures(sink['signatures']) or
                    sink['category'] not in list(Category) or sink['severity'] not in list(Severity) or
                    type(sink.get('cwe', [])) is not list or
                    any(type(c) is not str or not c.startswith('CWE-') or not c[4:].isdigit() for c in sink.get('cwe', [])) or
                    not _conditions(sink.get('required_conditions', []))):
                raise ValueError('Invalid or duplicate sink rule')
            ids.add(sink['id'])
        self.fingerprint = sha256(json.dumps(self.config, sort_keys=True).encode()).hexdigest()
        self.plugins: list[ProgrammaticRule] = []

    def register(self, rule: ProgrammaticRule):
        self.plugins.append(rule)

    def run_plugins(self, program: Program):
        return [finding for rule in self.plugins for finding in rule.analyze(program)]
