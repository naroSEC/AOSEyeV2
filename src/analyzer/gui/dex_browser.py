"""Cancellable provenance-aware DEX inventory. Unknown origins stay unknown."""


def dex_page(program, class_name='', query='', offset=0, limit=300, cancel=None,
             mode='classes', unit=None, package=None):
    query = query.casefold()
    classes, members = {}, {}
    def check():
        if cancel:
            cancel.check()
    def add_class(signature, origin):
        classes.setdefault(signature, set()).add(origin)
    for row in program.class_index:
        check()
        add_class(row['signature'], row.get('unit', ''))
    for signature, method in program.methods.items():
        check()
        owner = method.class_name or signature.split('->')[0]
        add_class(owner, method.unit)
        members[('method', signature, method.unit)] = bool(method.instructions)
    for row in program.method_index:
        check()
        if row.get('declared') is True:
            signature, origin = row['signature'], row.get('unit', '')
            add_class(signature.split('->')[0], origin)
            members.setdefault(('method', signature, origin), False)
    known_fields = set()
    for row in program.field_index:
        check()
        signature, origin = row['signature'], row.get('unit', '')
        known_fields.add(signature)
        members[('field', signature, origin)] = False
        add_class(signature.split('->')[0], origin)
    for signature in program.fields:
        check()
        if signature not in known_fields:
            members[('field', signature, '')] = False
            add_class(signature.split('->')[0], '')
    for signature in program.classes:
        check()
        if signature not in classes:
            add_class(signature, '')
    rows, seen = [], set()
    total = 0
    def add(name, kind, origin='', body=False, duplicate=False, matched=False):
        nonlocal total
        key = (name, kind, origin)
        if key in seen or (not matched and query not in name.casefold()):
            return
        seen.add(key)
        if offset <= total < offset + limit:
            rows.append(dict(name=name, kind=kind, unit=origin, has_body=body, duplicate=duplicate))
        total += 1
    if mode == 'units':
        for row in program.dex_units:
            check()
            add(row['id'], 'unit', row['id'])
        for origins in classes.values():
            check()
            for origin in sorted(origins):
                add(origin or 'Unknown unit', 'unit', origin)
        for _, _, origin in members:
            check()
            add(origin or 'Unknown unit', 'unit', origin)
    elif class_name:
        for (kind, signature, origin), body in members.items():
            check()
            if signature.split('->')[0] == class_name and (unit is None or origin == unit):
                add(signature, kind, origin, body, len(classes.get(class_name, ())) > 1)
    else:
        matching = set()
        if query and mode == 'classes':
            for (_, signature, origin) in members:
                check()
                if query in signature.casefold():
                    matching.add((signature.split('->')[0], origin))
        for signature, origins in classes.items():
            check()
            pkg = signature[1:].rsplit('/', 1)[0] if '/' in signature else '(default)'
            for origin in sorted(origins):
                if unit is not None and origin != unit:
                    continue
                if package is not None and package != pkg:
                    continue
                if mode == 'packages':
                    add(pkg, 'package', origin)
                else:
                    add(signature, 'class', origin, duplicate=len(origins) > 1,
                        matched=(signature, origin) in matching)
    check()
    return dict(items=rows, total=total, offset=offset, class_name=class_name,
                query=query, mode=mode, unit=unit, package=package,
                has_more=offset + len(rows) < total)
