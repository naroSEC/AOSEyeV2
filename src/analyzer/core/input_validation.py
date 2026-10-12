"""Strict external JSON boundary; no coercion or silent field dropping."""
import json
import math
from dataclasses import MISSING, fields, is_dataclass
from functools import lru_cache
from types import UnionType
from typing import Any, get_args, get_origin, get_type_hints


def read_json(path, max_bytes, cancel=None):
    def check():
        if cancel:
            cancel.check()
    def pairs(items):
        check()
        result = {}
        for index, (key, value) in enumerate(items):
            if index % 256 == 0:
                check()
            if key in result:
                raise ValueError('Duplicate JSON object key: ' + repr(key[:80]))
            result[key] = value
        return result

    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError('Non-finite JSON number is not supported')
        return result

    def constant(_):
        raise ValueError('Non-standard JSON numeric constant is not supported')

    try:
        check()
        with path.open('rb') as stream:
            if path.stat().st_size > max_bytes:
                raise ValueError(f'JSON file exceeds {max_bytes} byte limit')
            raw = bytearray()
            while len(raw) <= max_bytes:
                check()
                chunk = stream.read(min(1024 * 1024, max_bytes + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            del chunk
        if len(raw) > max_bytes:
            raise ValueError(f'JSON file exceeds {max_bytes} byte limit')
        text = raw.decode('utf-8-sig')
        del raw  # Do not retain the byte buffer while allocating the decoded model.
        check()
        value = json.loads(text, object_pairs_hook=pairs,
                           parse_float=number, parse_constant=constant)
        del text
        check()
        # Python decoder recursion limits vary by runtime; enforce our own depth policy.
        pending = [(iter((value,)), 0)]
        visited = 0
        while pending:
            visited += 1
            if visited % 256 == 0:
                check()
            iterator, depth = pending[-1]
            try:
                item = next(iterator)
            except StopIteration:
                pending.pop()
                continue
            if type(item) in (dict, list):
                if depth >= 64:
                    raise ValueError('Maximum JSON nesting depth is 64')
                pending.append((iter(item.values() if type(item) is dict else item), depth + 1))
        check()
        return value
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('Invalid JSON encoding or excessive nesting') from exc


@lru_cache(maxsize=None)
def model_fields(model):
    return ({f.name: f for f in fields(model)}, get_type_hints(model))


def validate(value, expected, where='$', depth=0, cancel=None):
    if expected is str and isinstance(value, str):
        return
    if expected in (int, bool, float) and type(value) is expected:
        return
    if cancel:
        cancel.check()
    def fail(reason):
        raise ValueError(f'{where}: {reason}')

    if depth > 64:
        fail('maximum nesting depth is 64')
    origin, args = get_origin(expected), get_args(expected)
    if origin is UnionType:
        if value is None and type(None) in args:
            return
        return validate(value, next(t for t in args if t is not type(None)), where, depth, cancel)
    if is_dataclass(expected):
        if type(value) is not dict:
            fail('expected object')
        schema, hints = model_fields(expected)
        for key in value:
            if key not in schema:
                fail('unknown field ' + repr(key[:80]))
        for key, field in schema.items():
            if key not in value:
                if field.default is MISSING and field.default_factory is MISSING:
                    fail('missing field ' + key)
                continue
            validate(value[key], hints[key], where + '.' + key, depth + 1, cancel)
        return
    if expected is Any:
        if value is None or type(value) in (str, bool, int):
            return
        if type(value) is float and math.isfinite(value):
            return
        if type(value) not in (dict, list):
            fail('expected JSON value')
        expected = type(value)
    if expected is list or origin is list:
        if type(value) is not list:
            fail('expected array')
        for index, item in enumerate(value):
            if cancel and index % 256 == 0:
                cancel.check()
            validate(item, args[0] if args else Any, f'{where}[{index}]', depth + 1, cancel)
    elif expected is dict or origin is dict:
        if type(value) is not dict:
            fail('expected object')
        for index, (key, item) in enumerate(value.items()):
            if cancel and index % 256 == 0:
                cancel.check()
            if type(key) is not str:
                fail('expected string key')
            validate(item, args[1] if args else Any, where + '[' + repr(key[:80]) + ']', depth + 1, cancel)
    elif type(value) is not expected:
        fail('expected ' + expected.__name__)


def validate_project(value, cancel=None):
    from analyzer.core.models import (AnalysisResult, Category, FindingType, Severity,
                                      Confidence, Verification)
    validate(value, AnalysisResult, cancel=cancel)
    if value.get('schema_version') != 1:
        raise ValueError('Unsupported project schema')
    # Keep historical short hash strings readable; live evidence separately checks the APK hash.
    ids = set()
    choices = dict(category=Category, type=FindingType, severity=Severity,
                   confidence=Confidence, verification=Verification,
                   analysis_level={'L0', 'L1', 'L2', 'L3', 'L4', 'L5'})
    for index, finding in enumerate(value.get('findings', [])):
        if cancel:
            cancel.check()
        for key, allowed in choices.items():
            if key in finding and finding[key] not in allowed:
                raise ValueError(f'$.findings[{index}].{key}: unsupported value')
        identity = finding.get('id')
        if identity and identity in ids:
            raise ValueError('Duplicate finding id')
        ids.add(identity)
        offset = finding.get('location', {}).get('offset')
        if offset is not None and offset < 0:
            raise ValueError('Finding offset must be nonnegative')
        for step in finding.get('data_flow', []):
            if cancel:
                cancel.check()
            for key, typ in (('label', str), ('method', str), ('offset', int)):
                if key not in step or type(step[key]) is not typ:
                    raise ValueError('Invalid data_flow step: ' + key)
            if step['offset'] < 0:
                raise ValueError('Flow offset must be nonnegative')
    for item in value.get('files', []):
        if cancel:
            cancel.check()
        if type(item.get('path')) is not str or type(item.get('size')) is not int or item['size'] < 0:
            raise ValueError('Invalid file inventory path/size')
    for signature, method in value.get('program', {}).get('methods', {}).items():
        if cancel:
            cancel.check()
        if method['signature'] != signature:
            raise ValueError('Method key/signature mismatch')
        offsets = set()
        for index, instruction in enumerate(method.get('instructions', [])):
            if cancel and index % 256 == 0:
                cancel.check()
            offset = instruction['offset']
            if offset < 0 or offset in offsets:
                raise ValueError('Instruction offsets must be unique and nonnegative')
            offsets.add(offset)
            for key in ('registers', 'defs', 'uses', 'successors'):
                for index, n in enumerate(instruction.get(key, [])):
                    if cancel and index % 256 == 0:
                        cancel.check()
                    if n < 0:
                        raise ValueError('Negative instruction register or successor')
    coverage = value.get('provenance', {}).get('flow_coverage', {})
    if type(coverage) is not dict or type(coverage.get('boundaries', [])) is not list:
        raise ValueError('Invalid flow_coverage/boundaries')
