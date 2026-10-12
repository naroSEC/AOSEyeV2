"""Exact normalized DEX locations. Never invent source-line mappings."""


def bytecode_location(program, signature, offset, unit=''):
    method = program.methods.get(signature)
    if method is None:
        raise ValueError('Method body is not indexed: ' + signature)
    if unit and unit != method.unit:
        raise ValueError('DEX unit mismatch; navigation refused')
    if type(offset) is not int or offset < 0:
        raise ValueError('An exact nonnegative DEX instruction offset is required')
    index = next((n for n, i in enumerate(method.instructions) if i.offset == offset), None)
    if index is None:
        raise ValueError('DEX instruction offset does not exist in this method')
    start, end = max(0, index - 12), min(len(method.instructions), index + 49)
    lines = [f'{signature}\nUnit: {method.unit or "not recorded"} · DEX offset 0x{offset:x}',
             f'Instructions {start + 1}–{end} / {len(method.instructions)}; >>> marks exact DEX evidence.',
             'No source-line mapping is inferred.\n']
    for instruction in method.instructions[start:end]:
        marker = '>>>' if instruction.offset == offset else '   '
        lines.append(f'{marker} {instruction.offset:04x}  ' + (instruction.text or
                     f'{instruction.opcode} {instruction.registers} {instruction.target}'))
    return dict(method=signature, offset=offset, unit=method.unit), '\n'.join(lines)


def reference_links(program, edges):
    links, seen = [], set()
    for edge in edges:
        candidates = [('Call site', edge['caller'], edge['offset'], edge['unit'])]
        target = program.methods.get(edge['callee'])
        if target and target.instructions:
            candidates.append(('Declared target', target.signature, target.instructions[0].offset, target.unit))
        for label, method, offset, unit in candidates:
            key = method, offset, unit
            if key not in seen:
                seen.add(key)
                links.append(dict(label=label, method=method, offset=offset, unit=unit))
    return links


def native_reference_page(program, element, page, cancel=None):
    """Recheck vendor references; labels supplied by a file/backend are not trusted."""
    from analyzer.core.graph import DeclarationResolver, verify_native_xref
    resolver = DeclarationResolver(program)
    items, links, seen = [], [], set()
    for original in page['items']:
        if cancel:
            cancel.check()
        item = verify_native_xref(program, element, original, resolver)
        allowed = item['target_validation'] in ('EXACT_DECLARED_TARGET', 'INHERITED_DECLARATION')
        reason = 'Target is different or could not be verified'
        if allowed:
            method = program.methods.get(item['caller'])
            # Navigation needs unit identity in addition to the operand comparison.
            allowed = bool(method and method.unit and item.get('unit') == method.unit)
            reason = 'Missing or mismatched DEX unit'
        if allowed:
            key = item['caller'], item['offset'], item['unit']
            if key not in seen:
                seen.add(key)
                links.append(dict(label='Verified JEB reference · ' + item['target_validation'],
                                  method=key[0], offset=key[1], unit=key[2]))
            reason = 'DEX unit, instruction offset and target verified; not proof of execution'
        item.update(navigation_allowed=allowed, navigation_reason=reason)
        items.append(item)
    result = dict(page, items=items, requested_element=element,
                  shown=len(items), has_more=page.get('offset', 0) + len(items) < page['total'],
                  navigation_policy='Only DEX-verified same-target references with a matching unit are linked')
    return result, links
