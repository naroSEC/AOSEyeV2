"""Trust-source inventory. Does not validate certificates or TLS connections."""
import re
from defusedxml import ElementTree as ET


def parse_trust(data, target_sdk, debuggable, cancel):
    cancel.check()
    root = ET.fromstring(data)
    if root.tag != 'network-security-config' or len(list(root.iter())) > 2000:
        raise ValueError('Invalid or oversized network trust XML')
    diagnostics = []
    def anchors(node, inherited, debug=False):
        blocks = node.findall('trust-anchors') if node is not None else []
        if len(blocks) > 1:
            raise ValueError('Multiple trust-anchors elements')
        if not blocks:
            return inherited
        values = []
        for cert in blocks[0]:
            cancel.check()
            if cert.tag != 'certificates':
                raise ValueError('Unsupported trust-anchors child')
            source = cert.get('src', '')
            kind = source.upper() if source in ('system', 'user') else (
                'RESOURCE' if re.fullmatch(r'@(?:raw/[A-Za-z0-9_]+|(?:0x)?[0-9a-fA-F]{8})', source) else 'UNKNOWN')
            raw = cert.get('overridePins')
            override = debug if raw is None else True if raw == 'true' else False if raw == 'false' else None
            if kind == 'UNKNOWN' or override is None:
                diagnostics.append('Unresolved certificate source or overridePins value')
            if kind == 'RESOURCE':
                diagnostics.append('Referenced CA resource content/validity is not verified')
            values.append(dict(source=source, kind=kind, override_pins=override,
                               origin='EXPLICIT', certificate_contents='NOT_INSPECTED'))
        return values
    defaults = None
    if type(target_sdk) is int:
        defaults = [dict(source=s, kind=s.upper(), override_pins=False, origin='TARGET_SDK_DEFAULT_MODEL',
                         certificate_contents='NOT_INSPECTED')
                    for s in (('system', 'user') if target_sdk <= 23 else ('system',))]
    else:
        diagnostics.append('Target SDK unresolved; platform trust defaults are unknown')
    bases, debug_blocks = root.findall('base-config'), root.findall('debug-overrides')
    if len(bases) > 1 or len(debug_blocks) > 1:
        raise ValueError('Duplicate base-config or debug-overrides')
    base = anchors(bases[0] if bases else None, defaults)
    active = False if not debug_blocks else debuggable
    debug_sources = anchors(debug_blocks[0], [], True) if debug_blocks else []
    if active is None:
        diagnostics.append('Debuggable value unresolved; debug trust application is unknown')
    domains = []
    def visit(node, inherited, depth):
        cancel.check()
        if depth > 32:
            raise ValueError('Trust inheritance depth budget exceeded')
        selected = anchors(node, inherited)
        for domain in node.findall('domain'):
            domains.append(dict(domain=(domain.text or '').strip().lower(), anchors=selected))
        for child in node.findall('domain-config'):
            visit(child, selected, depth + 1)
    for node in root.findall('domain-config'):
        visit(node, base, 1)
    return dict(base_anchors=base, domains=domains,
                debug_overrides=dict(present=bool(debug_blocks), active=active, anchors=debug_sources),
                diagnostics=sorted(set(diagnostics)),
                scope='Declared/inherited trust sources in supplied configuration; standard target-SDK defaults modeled. '
                      'Privileged-app/platform differences, CA contents, certificate chains and pin-set semantics are not verified.')


def select_trust_inventory(trust, matched_domain):
    anchors = trust.get('base_anchors')
    if matched_domain is not None:
        rows = [row for row in trust.get('domains', []) if row.get('domain') == matched_domain]
        if len(rows) != 1:
            return dict(status='UNKNOWN', reason='Trust domain inventory missing or ambiguous')
        anchors = rows[0].get('anchors')
    debug = trust.get('debug_overrides', {})
    effective = None if anchors is None or debug.get('active') is None else (
        list(anchors) + (debug.get('anchors', []) if debug.get('active') else []))
    return dict(anchors=anchors, debug_overrides=debug, combined_sources=effective,
                scope=trust.get('scope'), diagnostics=trust.get('diagnostics', []))
