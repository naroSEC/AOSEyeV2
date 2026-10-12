"""Saved exact DEX operand coverage, not inheritance or runtime dispatch resolution."""
from collections import Counter

STATUSES = ('body_available', 'ambiguous_units', 'unknown_origin', 'indexed_body_missing',
            'declared_no_code', 'declaration_unknown', 'unindexed_target', 'missing_operand')


def call_coverage(program, cancel=None, *, _visit=None):
    def check():
        if cancel:
            cancel.check()
    declarations = {}
    for n, row in enumerate(program.method_index):
        if n % 256 == 0:
            check()
        signature = row.get('signature')
        if not isinstance(signature, str):
            continue
        entry = declarations.setdefault(signature, dict(units=set(), unknown=False, code=False, no_code=False))
        if row.get('declared') is True:
            unit = row.get('unit')
            if isinstance(unit, str) and unit:
                entry['units'].add(unit)
            else:
                entry['unknown'] = True
            entry['code'] |= row.get('has_code') is True
            entry['no_code'] |= row.get('has_code') is False
        elif row.get('declared') is not False:
            entry['unknown'] = True
    counts = Counter({key: 0 for key in STATUSES})
    dispatch = 0
    scanned = 0
    for method in program.methods.values():
        check()
        for n, ins in enumerate(method.instructions):
            if n % 256 == 0:
                check()
            scanned += 1
            if not ins.opcode.startswith('invoke'):
                continue
            dispatch += int(ins.opcode.startswith(('invoke-virtual', 'invoke-interface',
                                                  'invoke-custom', 'invoke-polymorphic')))
            target = ins.target
            if not target or '->' not in target:
                counts['missing_operand'] += 1
                if _visit:
                    _visit(method, ins, 'missing_operand')
                continue
            entry = declarations.get(target, {})
            body = program.methods.get(target)
            units = entry.get('units', set())
            # Do not mutate declaration metadata while accounting for a retained body.
            origins = units | ({body.unit} if body and body.unit else set())
            if len(origins) > 1:
                status = 'ambiguous_units'
            elif entry.get('unknown') or (body is not None and not body.unit):
                status = 'unknown_origin'
            elif body is not None:
                status = 'body_available'
            elif entry.get('code'):
                status = 'indexed_body_missing'
            elif entry.get('no_code'):
                status = 'declared_no_code'
            elif units:
                status = 'declaration_unknown'
            else:
                status = 'unindexed_target'
            counts[status] += 1
            if _visit:
                _visit(method, ins, status)
    check()
    return dict(schema=1, scope='saved_exact_operands', caller_bodies=len(program.methods),
                instructions_scanned=scanned, invoke_sites=sum(counts.values()), counts=dict(counts),
                dynamic_dispatch_sites=dispatch)


def call_target_page(program, status='UNAVAILABLE', offset=0, limit=100, cancel=None):
    if status not in ('ALL', 'UNAVAILABLE') + STATUSES:
        raise ValueError('Invalid call-target filter')
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 300:
        raise ValueError('Invalid call-target page bounds')
    rows, total = [], 0
    last_method, offsets = None, Counter()
    def visit(method, ins, classification):
        nonlocal total, last_method, offsets
        if status == 'UNAVAILABLE' and classification == 'body_available':
            return
        if status not in ('ALL', 'UNAVAILABLE', classification):
            return
        total += 1
        if total <= offset or len(rows) >= limit:
            return
        if last_method is not method:
            last_method, offsets = method, Counter()
            for n, instruction in enumerate(method.instructions):
                if cancel and n % 256 == 0:
                    cancel.check()
                offsets[instruction.offset] += 1
        allowed = bool(method.unit) and type(ins.offset) is int and ins.offset >= 0 and offsets[ins.offset] == 1
        rows.append(dict(caller=method.signature, unit=method.unit, offset=ins.offset,
                         opcode=ins.opcode, target=ins.target, status=classification,
                         navigation_allowed=allowed))
    call_coverage(program, cancel, _visit=visit)
    return dict(items=rows, total=total, offset=offset, shown=len(rows),
                has_more=offset + len(rows) < total, status=status,
                scope='Recomputed from saved operands only; not whole-APK or runtime coverage')


def coverage_text(value, details=False):
    """Only show coherent saved counters. Never infer old results from current settings."""
    if not isinstance(value, dict) or value.get('schema') != 1 or value.get('scope') != 'saved_exact_operands':
        return 'Call-target coverage: not recorded.'
    counts = value.get('counts')
    if not isinstance(counts, dict) or set(counts) != set(STATUSES):
        return 'Call-target coverage: unavailable (invalid saved counters).'
    numbers = list(counts.values()) + [value.get(k) for k in
        ('caller_bodies', 'instructions_scanned', 'invoke_sites', 'dynamic_dispatch_sites')]
    if any(type(n) is not int or not 0 <= n <= 10**12 for n in numbers):
        return 'Call-target coverage: unavailable (invalid saved counters).'
    total = value['invoke_sites']
    if sum(counts.values()) != total or value['dynamic_dispatch_sites'] > total or total > value['instructions_scanned']:
        return 'Call-target coverage: unavailable (invalid saved counters).'
    summary = ('Saved exact call sites: %s; target body available %s; ambiguous units %s; '
            'other unavailable/unknown %s. Not runtime dispatch or whole-APK coverage.' %
            (total, counts['body_available'], counts['ambiguous_units'],
             total - counts['body_available'] - counts['ambiguous_units']))
    if not details:
        return summary
    return summary + '\n' + '\n'.join('%s: %s' % (key, counts[key]) for key in STATUSES) + (
        '\nDynamic-dispatch opcode sites (overlaps above): %s\n'
        'Unindexed targets can include platform/library APIs; missing bodies are not vulnerabilities. '
        'Inherited targets and runtime dispatch are not resolved by these counters.' % value['dynamic_dispatch_sites'])
