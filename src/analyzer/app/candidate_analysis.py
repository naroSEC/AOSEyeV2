"""Explicit bounded expansion into a fresh analysis; imported evidence is reverified live."""
from copy import deepcopy
from pathlib import Path

from analyzer.app.application import AnalysisApplication
from analyzer.app.candidate_artifact import validate_artifact, compare_origin, body_digest
from analyzer.backends.jeb.backend import file_hash
from analyzer.core.models import Program

MAX_ADDED_METHODS = 8
MAX_ADDED_BYTES = 2 * 1024 * 1024


def expand_candidate(original, artifact, backend, settings, cancel, progress=lambda *_: None):
    validate_artifact(artifact)
    cancel.check()
    if compare_origin(artifact, original)['status'] != 'SAVED_METADATA_MATCH':
        raise ValueError('Candidate origin does not match saved project metadata')
    prior = original.provenance.get('candidate_expansions', [])
    if not isinstance(prior, list) or len(prior) >= MAX_ADDED_METHODS:
        raise ValueError('Expansion count budget reached or invalid')
    if any(not isinstance(p, dict) or type(p.get('encoded_bytes')) is not int or p['encoded_bytes'] < 0 for p in prior):
        raise ValueError('Invalid expansion history')
    c = artifact['candidate']
    if sum(p['encoded_bytes'] for p in prior) + c['encoded_bytes'] > MAX_ADDED_BYTES:
        raise ValueError('Expansion byte budget reached')
    path = Path(original.input_path)
    if file_hash(path, cancel) != original.sha256:
        raise ValueError('Original input changed; expansion refused')
    old_program, old_path, old_hash = backend.program, backend.input_path, backend.input_sha256
    try:
        backend.program, backend.input_path, backend.input_sha256 = original.program, path, original.sha256
        progress(5, 'Reverifying candidate against original APK / DEX')
        live = backend.preview_call_target(c['caller'], c['offset'], cancel, max_bytes=c['byte_limit'])
        if live['status'] != 'CANDIDATE' or body_digest(live['method']) != artifact['body_sha256']:
            raise ValueError('Candidate differs from live JEB evidence or exceeds budget')
        cancel.check()
        program = deepcopy(original.program)
        cancel.check()
        target = live['method']['signature']
        program.methods[target] = Program.from_dict({'methods': {target: live['method']}}, cancel=cancel).methods[target]
        program.diagnostics.append('Explicit candidate expansion; saved declaration scope remains bounded; partial analysis')
        backend.program = program

        class ExpandedBackend:
            version = backend.version
            def load(self, requested, token):
                if file_hash(requested, token) != original.sha256:
                    raise ValueError('Original input changed during expansion')
                return program
            def __getattr__(self, name):
                return getattr(backend, name)

        result = AnalysisApplication(settings, ExpandedBackend()).analyze(path, cancel, progress)
        if result.program is not program or file_hash(path, cancel) != original.sha256:
            raise ValueError('Expansion analysis failed or input changed')
        result.notes = deepcopy(original.notes)
        result.provenance['candidate_expansions'] = deepcopy(prior) + [dict(
            target=target, unit=live['method']['unit'], caller=c['caller'], caller_unit=c['caller_unit'],
            offset=c['offset'], body_sha256=artifact['body_sha256'], encoded_bytes=live['encoded_bytes'],
            original_query_utc=artifact['queried_at_utc'], reverified_backend_version=backend.version)]
        result.provenance['parent_rules_sha256'] = original.provenance.get('rules_sha256')
        result.provenance['expansion_policy'] = 'explicit-live-reverified-one-hop; max 8 bodies / 2MiB; full saved-scope rule rerun'
        result.complete = False
        cancel.check()
        return result
    finally:
        backend.program, backend.input_path, backend.input_sha256 = old_program, old_path, old_hash
