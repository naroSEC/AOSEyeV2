"""Separate candidate evidence: bounded, validated, never a project or authenticity proof."""
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile

from analyzer.app.project_manager import write_json
from analyzer.core.input_validation import read_json, validate
from analyzer.core.models import Method

MAX_BYTES = 2 * 1024 * 1024


def body_digest(method):
    return sha256(json.dumps(method, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                             allow_nan=False).encode('ascii')).hexdigest()


def snapshot(candidate, backend_version):
    return dict(kind='aoseye-call-candidate', schema=1,
                queried_at_utc=datetime.now(timezone.utc).isoformat(),
                backend_version=backend_version, candidate=deepcopy(candidate),
                body_sha256=body_digest(candidate['method']))


def validate_artifact(value):
    if not isinstance(value, dict) or set(value) != {'kind', 'schema', 'queried_at_utc', 'backend_version', 'candidate', 'body_sha256'}:
        raise ValueError('Invalid candidate artifact envelope')
    if value['kind'] != 'aoseye-call-candidate' or type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Unsupported candidate artifact')
    if not isinstance(value['backend_version'], str) or not 1 <= len(value['backend_version']) <= 256:
        raise ValueError('Invalid backend version')
    timestamp = value['queried_at_utc']
    if not isinstance(timestamp, str) or len(timestamp) > 64:
        raise ValueError('Invalid query timestamp')
    parsed = datetime.fromisoformat(timestamp)
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError('Query timestamp must be UTC')
    candidate = value['candidate']
    keys = {'status', 'method', 'encoded_bytes', 'byte_limit', 'input_sha256', 'caller',
            'caller_unit', 'opcode', 'offset', 'scope'}
    if not isinstance(candidate, dict) or set(candidate) != keys or candidate['status'] != 'CANDIDATE':
        raise ValueError('Invalid candidate payload')
    for key in ('caller', 'caller_unit', 'opcode', 'scope', 'input_sha256'):
        if not isinstance(candidate[key], str) or not candidate[key]:
            raise ValueError('Missing candidate origin: ' + key)
    if not re.fullmatch('[0-9a-f]{64}', candidate['input_sha256']):
        raise ValueError('Invalid input fingerprint')
    if candidate['opcode'] not in ('invoke-static', 'invoke-static/range', 'invoke-direct', 'invoke-direct/range'):
        raise ValueError('Unsupported call opcode')
    if type(candidate['offset']) is not int or candidate['offset'] < 0:
        raise ValueError('Invalid caller offset')
    limit = candidate['byte_limit']
    if type(limit) is not int or not 1 <= limit <= 1048576:
        raise ValueError('Invalid candidate byte limit')
    method = candidate['method']
    validate(method, Method)
    if not method.get('unit') or not method.get('signature'):
        raise ValueError('Missing candidate identity')
    size = len((json.dumps(method, ensure_ascii=True) + '\n').encode('ascii'))
    if type(candidate['encoded_bytes']) is not int or candidate['encoded_bytes'] != size or size > limit:
        raise ValueError('Candidate byte accounting mismatch')
    if value['body_sha256'] != body_digest(method):
        raise ValueError('Candidate body digest mismatch')
    return value


def save_candidate(path, value):
    """Publish a complete new file atomically. Existing files are never overwritten."""
    validate_artifact(value)
    path = Path(path)
    if not path.name.endswith('.candidate.json'):
        raise ValueError('Use a new .candidate.json filename')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.aoseye-candidate-', dir=path.parent)
    os.close(fd)
    try:
        write_json(Path(temporary), value, compact=True, max_bytes=MAX_BYTES)
        os.link(temporary, path)  # Atomic no-clobber; unsupported filesystems fail safely.
    finally:
        Path(temporary).unlink(missing_ok=True)


def open_candidate(path, cancel=None):
    value = validate_artifact(read_json(Path(path), MAX_BYTES, cancel=cancel))
    if cancel:
        cancel.check()
    return value


def compare_origin(value, result):
    """Compare saved metadata only; this is not a live APK or authenticity verification."""
    validate_artifact(value)
    if result is None:
        return dict(status='NO_PROJECT', checks={}, warning='Unsigned candidate; no project to compare')
    c = value['candidate']
    caller = result.program.methods.get(c['caller'])
    sites = [i for i in caller.instructions if i.offset == c['offset']] if caller else []
    target = c['method']['signature']
    rows = [r for r in result.program.method_index if r.get('signature') == target and r.get('declared') is not False]
    checks = dict(input_sha256=result.sha256 == c['input_sha256'],
                  caller_unit=bool(caller and caller.unit == c['caller_unit']),
                  call_operand=len(sites) == 1 and sites[0].target == target and sites[0].opcode == c['opcode'],
                  target_declaration=bool(rows) and all(r.get('declared') is True and r.get('has_code') is True
                      and r.get('unit') == c['method']['unit'] for r in rows),
                  backend_version=result.provenance.get('version') == value['backend_version'])
    return dict(status='SAVED_METADATA_MATCH' if all(checks.values()) else 'MISMATCH_OR_UNKNOWN',
                checks=checks, warning='Unsigned candidate; matching saved metadata does not authenticate its body or verify the live APK')
