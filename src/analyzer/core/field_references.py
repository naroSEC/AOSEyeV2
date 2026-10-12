"""Bounded field operand references, not field declaration/runtime resolution."""

_ACCESS = {base + suffix: access for base, access in (
    ('iget', 'READ'), ('sget', 'READ'), ('iput', 'WRITE'), ('sput', 'WRITE'))
    for suffix in ('', '-wide', '-object', '-boolean', '-byte', '-char', '-short')}


def field_references(program, signature, unit='', limit=300, cancel=None, offset=0, access='ALL'):
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError('Field reference limit must be between 1 and 10000')
    if type(offset) is not int or offset < 0:
        raise ValueError('Field reference offset must be nonnegative')
    if access not in ('ALL', 'READ', 'WRITE'):
        raise ValueError('Field access filter must be ALL, READ or WRITE')
    items, links = [], []
    total = 0
    for key, method in program.methods.items():
        if cancel:
            cancel.check()
        if unit and method.unit != unit:
            continue
        offsets = None
        valid_offsets = True
        for n, ins in enumerate(method.instructions):
            if cancel and n % 256 == 0:
                cancel.check()
            if ins.target != signature or ins.opcode not in _ACCESS:
                continue
            operation = _ACCESS[ins.opcode]
            if access != 'ALL' and access != operation:
                continue
            total += 1
            if total <= offset or len(items) == limit:
                continue
            # Only current-page candidates with a known unit can become links.
            # Count-only and unknown-origin queries need no offset index.
            if unit and key == method.signature and offsets is None:
                offsets = {}
                for j, candidate in enumerate(method.instructions):
                    if cancel and j % 256 == 0:
                        cancel.check()
                    if type(candidate.offset) is int and candidate.offset >= 0:
                        offsets[candidate.offset] = offsets.get(candidate.offset, 0) + 1
                    else:
                        valid_offsets = False
            allowed = bool(valid_offsets and unit and method.unit == unit and key == method.signature
                           and type(ins.offset) is int and ins.offset >= 0
                           and offsets.get(ins.offset) == 1)
            reason = ('Exact field operand, opcode, unit and unique DEX offset verified'
                      if allowed else 'Unknown selected unit or invalid/ambiguous DEX location')
            item = dict(method=key, unit=method.unit, offset=ins.offset,
                        opcode=ins.opcode, access=operation, field=ins.target,
                        navigation_allowed=allowed, navigation_reason=reason)
            items.append(item)
            if allowed:
                links.append(dict(method=key, unit=method.unit, offset=ins.offset,
                                  label='Field ' + operation + ' · exact operand'))
    if cancel:
        cancel.check()
    has_more = offset + len(items) < total
    return dict(field=signature, unit=unit, items=items, shown=len(items), truncated=has_more,
                offset=offset, total=total, access=access, has_more=has_more,
                scope='Selected JEB unit' if unit else 'All saved bodies; selected field unit UNKNOWN',
                evidence_origin='Saved DEX field operands',
                limitations='Exact operand matching only; no inherited-field resolution, declaration identity, '
                            'runtime execution or completeness proof. Unindexed bodies are not searched.'), links
