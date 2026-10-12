"""Saved pin declarations and date-granularity review; not TLS enforcement proof."""
import base64
import binascii
from datetime import date, datetime, timezone
import re
from defusedxml import ElementTree as ET


def parse_pins(data, cancel, as_of=None):
    cancel.check()
    as_of = as_of or datetime.now(timezone.utc).date()
    root = ET.fromstring(data)
    if root.tag != 'network-security-config' or len(list(root.iter())) > 2000:
        raise ValueError('Invalid or oversized pin XML')
    for parent in root.iter():
        if parent.tag != 'domain-config' and parent.find('pin-set') is not None:
            raise ValueError('pin-set outside domain-config')
    diagnostics, domains, declarations = [], [], []
    def block(node, inherited):
        blocks = node.findall('pin-set')
        if len(blocks) > 1:
            raise ValueError('Multiple pin-set elements')
        if not blocks:
            return inherited
        item = blocks[0]
        expiration = item.get('expiration')
        state = 'NO_EXPIRATION'
        if expiration is not None:
            try:
                if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', expiration):
                    raise ValueError('Invalid date format')
                expires = date.fromisoformat(expiration)
                state = 'PAST_EXPIRATION_DATE' if expires < as_of else (
                    'BEFORE_EXPIRATION_DATE' if expires > as_of else 'EXPIRATION_DAY_UNCERTAIN')
            except ValueError:
                state = 'UNKNOWN'
                diagnostics.append('Unresolved or invalid pin expiration date')
        pins, unique = [], set()
        if len(item) > 64:
            raise ValueError('Pin count budget exceeded')
        for pin in item:
            cancel.check()
            if pin.tag != 'pin' or len(pin):
                raise ValueError('Invalid pin-set child')
            algorithm = pin.get('digest', '')
            value = (pin.text or '').strip()
            valid = False
            if algorithm == 'SHA-256' and len(value) <= 256:
                try:
                    decoded = base64.b64decode(value, validate=True)
                    valid = len(decoded) == 32
                    if valid:
                        unique.add(decoded)
                except (ValueError, binascii.Error):
                    pass
            if not valid:
                diagnostics.append('Unsupported pin algorithm or invalid/unresolved SHA-256 digest')
            pins.append(dict(digest=algorithm, value=value[:256], truncated=len(value) > 256,
                             validation='SHA256_BASE64_32_BYTES' if valid else 'UNKNOWN'))
        result = dict(expiration=expiration, expiration_state=state, pins=pins,
                      valid_unique_pin_count=len(unique), declared_pin_count=len(pins),
                      empty=not pins, certificate_match='NOT_VERIFIED')
        declarations.append(result)
        return result
    def visit(node, inherited, depth):
        cancel.check()
        if depth > 32:
            raise ValueError('Pin inheritance depth budget exceeded')
        selected = block(node, inherited)
        for domain in node.findall('domain'):
            domains.append(dict(domain=(domain.text or '').strip().lower(), pin_set=selected))
        for child in node.findall('domain-config'):
            visit(child, selected, depth + 1)
    for node in root.findall('domain-config'):
        visit(node, None, 1)
    return dict(as_of_date=as_of.isoformat(), date_basis='UTC date; expiration-day boundary is not resolved',
                domains=domains, declarations=declarations, diagnostics=sorted(set(diagnostics)),
                scope='NSC declarations only. Absence is not a vulnerability or proof of no code-level pinning. '
                      'Distinct pins do not prove a usable backup. Trust override conditions, device clocks, '
                      'certificate matches and actual enforcement remain unverified.')


def select_pin_inventory(inventory, domain):
    rows = [r for r in inventory.get('domains', []) if r.get('domain') == domain] if domain else []
    return dict(pin_set=rows[0].get('pin_set') if len(rows) == 1 else None,
                status='DECLARED' if len(rows) == 1 and rows[0].get('pin_set') is not None else 'NO_SELECTED_DECLARATION',
                as_of_date=inventory.get('as_of_date'), date_basis=inventory.get('date_basis'),
                scope=inventory.get('scope'), diagnostics=inventory.get('diagnostics', []))
