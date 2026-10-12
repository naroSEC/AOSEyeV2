"""Conservative handler edges, independent of exception type feasibility."""


def exception_edges(method, code):
    if method.exception_status not in ('NONE', 'PRESENT'):
        raise ValueError('Exception metadata unknown; reindex required')
    regions = method.exception_regions
    if method.exception_status == 'NONE':
        if regions or any(i.opcode == 'move-exception' for i in code.values()):
            raise ValueError('Exception table contradicts method instructions')
        return {}
    if not regions or len(regions) > 64 or any(i.normal_successors is None for i in code.values()):
        raise ValueError('Exception regions/normal successors missing or region limit exceeded')
    edges, previous_end, entries = {}, -1, set()
    if any(type(r.get('start')) is not int for r in regions):
        raise ValueError('Invalid exception region start')
    for region in sorted(regions, key=lambda r: r['start']):
        start, end = region['start'], region.get('end')
        if type(end) is not int or start not in code or end not in code or start >= end or start < previous_end:
            raise ValueError('Unaligned, overlapping or invalid exception region')
        previous_end = end
        handlers = region.get('handlers')
        if not isinstance(handlers, list) or not handlers or len(handlers) > 64:
            raise ValueError('Missing or excessive exception handlers')
        addresses = set()
        for handler in handlers:
            if not isinstance(handler, dict):
                raise ValueError('Invalid exception handler record')
            address = handler.get('address')
            if type(address) is not int or address not in code:
                raise ValueError('Exception handler address is not an indexed instruction')
            addresses.add(address)
        entries.update(addresses)
        for offset in code:
            if start <= offset < end:
                edges[offset] = sorted(addresses)
    if any(i.opcode == 'move-exception' and i.offset not in entries for i in code.values()):
        raise ValueError('Unmapped exception handler instruction')
    return edges
