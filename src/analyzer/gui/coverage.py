"""Saved coverage labels, never a claim that absent rows do not exist in the APK."""
import re
from analyzer.core.call_coverage import coverage_text


def index_policy_label(result):
    if result is None:
        return ''
    known = ('native', 'manifest-first')
    requested = result.provenance.get('requested_index_order')
    requested = requested if requested in known else 'unknown (not recorded)'
    effective = result.program.capabilities.get('index_order')
    suffix = ' (within each JEB unit; not ownership/entrypoint proof)'
    global_suffix = ' (global across JEB units; not ownership/entrypoint proof)'
    scope = ('Global priority across JEB units (per declaration kind).' if effective == 'manifest-first' + global_suffix
             else 'Priority is within each JEB unit only.' if effective in tuple(p + suffix for p in known)
             else 'Collection scope is native or not recorded.')
    effective = next((p for p in known if effective in (p, p + suffix, p + global_suffix)), 'unknown (not recorded)')
    return ('Saved index policy: requested %s; effective %s.\n'
            '%s Not proof of ownership or executable entrypoints.'
            % (requested, effective, scope))


def coverage_label(result):
    if result is None:
        return ''
    program = result.program
    messages = list(dict.fromkeys(program.diagnostics[-256:] + result.diagnostics[-256:]))
    budget = [d for d in messages if d.startswith('Declaration index budget exhausted;')]
    partial = not result.complete or bool(program.diagnostics) or bool(result.diagnostics)
    status = 'PARTIAL ANALYSIS' if partial else 'Saved analysis marked complete (configured scope only)'
    counts = ('Saved index: classes %s · fields %s · methods %s · bodies %s'
              % (len(program.class_index) if program.class_index else len(program.classes),
                 len(program.field_index) if program.field_index else len(program.fields),
                 len(program.method_index), len(program.methods)))
    exclusions = 'Excluded totals are not available in this saved result.' if partial else ''
    if len(budget) == 1:
        match = re.search(r'\bomitted_classes=(\d{1,12}) omitted_fields=(\d{1,12}) omitted_methods=(\d{1,12})(?:;|$)', budget[0])
        if match:
            exclusions = 'Reported exclusions: classes %s · fields %s · methods %s.' % match.groups()
    return '\n'.join(s for s in (status + ' · ' + counts, exclusions, index_policy_label(result),
        coverage_text(result.provenance.get('call_target_coverage')),
        'Search covers saved data only. No match is not proof of absence in the APK; see Diagnostics.') if s)
