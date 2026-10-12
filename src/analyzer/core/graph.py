from analyzer.core.models import Program
import re


class DeclarationResolver:
    """Per-pass snapshot of declaration metadata, never a global mutable cache."""
    def __init__(self, program):
        self.program = program
        self.declarations = set()
        self.unknown = set()
        self.diagnostics = set()
        for item in program.method_index:
            signature = item.get('signature')
            if not isinstance(signature, str):
                continue
            if item.get('declared') is True:
                self.declarations.add(signature)
            elif item.get('declared') is not False:
                self.unknown.add(signature)

    def resolve(self, signature):
        if '->' not in signature:
            return signature, 'NON_METHOD'
        owner, member = signature.split('->', 1)
        seen = set()
        while owner not in seen:
            seen.add(owner)
            candidate = owner + '->' + member
            if candidate in self.program.methods:
                return candidate, 'EXACT' if candidate == signature else 'INHERITED_DECLARATION'
            if candidate in self.declarations:
                self.diagnostics.add('Declared method has no indexed body: ' + candidate)
                return candidate, 'DECLARED_NO_BODY'
            if candidate in self.unknown:
                self.diagnostics.add('Legacy declaration metadata unavailable; reindex required: ' + candidate)
                return candidate, 'UNKNOWN_DECLARATION'
            parent = self.program.class_hierarchy.get(owner)
            if not parent:
                return candidate, 'UNINDEXED_REFERENCE'
            # Constructors and class initializers are not inherited.
            if member.startswith(('<init>(', '<clinit>(')):
                return signature, 'UNINDEXED_REFERENCE'
            owner = parent
        self.diagnostics.add('Declaration hierarchy cycle: ' + signature)
        return signature, 'HIERARCHY_CYCLE'

    def target(self, signature):
        return self.resolve(signature)[0]


def declared_target(program: Program, signature: str) -> str:
    """Compatibility helper; bulk consumers should reuse a per-pass resolver."""
    return DeclarationResolver(program).target(signature)


def verify_native_xref(program: Program, element: str, reference: dict, resolver=None) -> dict:
    """Retain the vendor reference, separately check its actual DEX operand."""
    result = dict(reference, target_validation='UNVERIFIED')
    address = reference.get('address', '')
    if not isinstance(address, str):
        return result
    match = re.fullmatch(r'(.*)\+([0-9a-fA-F]{1,16})h', address)
    if not match:
        return result
    caller, offset = match[1], int(match[2], 16)
    method = program.methods.get(caller)
    if not method or (reference.get('unit') and method.unit and reference['unit'] != method.unit):
        return result
    ins = next((i for i in method.instructions if i.offset == offset), None)
    if not ins or not ins.target:
        return result
    resolver = resolver or DeclarationResolver(program)
    resolved, status = resolver.resolve(ins.target) if ins.opcode.startswith('invoke') else (ins.target, 'NON_METHOD')
    result.update(caller=caller, offset=offset, raw_declared_target=ins.target,
                  resolved_declared_target=resolved, resolution=status,
                  target_validation='EXACT_DECLARED_TARGET' if ins.target == element else
                  'INHERITED_DECLARATION' if resolved == element and status in ('INHERITED_DECLARATION', 'DECLARED_NO_BODY') else
                  'UNVERIFIED' if status in ('UNKNOWN_DECLARATION', 'HIERARCHY_CYCLE') else 'DIFFERENT_DECLARED_TARGET')
    return result


def reference_query(program, element=None, limit=300, cancel=None, invokes_only=True, incoming_only=False):
    """Bounded DEX references with raw operand and shared declaration resolution.

    This is not a runtime dispatch graph. Scan is cancellable even with no matches.
    """
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError('Reference limit must be between 1 and 10000')
    edges = []
    resolver = DeclarationResolver(program)
    for method in program.methods.values():
        if cancel:
            cancel.check()
        for index, instruction in enumerate(method.instructions):
            if cancel and index % 256 == 0:
                cancel.check()
            invoke = instruction.opcode.startswith('invoke')
            if not instruction.target or (invokes_only and not invoke):
                continue
            raw = instruction.target
            resolved, status = resolver.resolve(raw) if invoke else (raw, 'NON_METHOD')
            targets = (raw, resolved) if incoming_only else (method.signature, raw, resolved)
            if element is not None and element not in targets:
                continue
            if len(edges) == limit:
                return dict(edges=edges, truncated=True, diagnostics=sorted(resolver.diagnostics), evidence_origin='DEX operands; declared resolution, not runtime dispatch')
            edges.append(dict(caller=method.signature, callee=resolved, offset=instruction.offset,
                              unit=method.unit, opcode=instruction.opcode, raw_declared_target=raw,
                              resolved_declared_target=resolved,
                              resolution=status))
    return dict(edges=edges, truncated=False, diagnostics=sorted(resolver.diagnostics),
                evidence_origin='DEX operands; declared resolution, not runtime dispatch')
