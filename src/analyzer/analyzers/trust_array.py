"""Bounded TrustManager arrays -> SSLContext.init, without provider-selection claims."""
from analyzer.analyzers.tls import _linear
from analyzer.core.models import Finding, Location

ARRAY = '[Ljavax/net/ssl/TrustManager;'
INIT = 'Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V'


def trust_array_context(program, callbacks, cancel):
    candidates = {f.location.class_name: f for f in callbacks
                  if f.rule_id == 'AOS-TLS-001' and f.type == 'WEAKNESS'}
    findings = []
    for method in program.methods.values():
        cancel.check()
        if not any(i.target == INIT for i in method.instructions) or not _linear(method):
            continue
        regs, objects, arrays, pending = {}, {}, {}, None
        for ins in method.instructions:
            cancel.check()
            op, rr = ins.opcode, ins.registers
            old, previous_pending = dict(regs), pending
            pending = None
            for reg in ins.defs:
                regs.pop(reg, None)
            if op in ('const/4', 'const/16', 'const', 'const/high16') and len(rr) == 1:
                regs[rr[0]] = ('int', ins.literal) if type(ins.literal) is int else None
            elif op in ('move-object', 'move-object/from16', 'move-object/16', 'move', 'move/from16', 'move/16') and len(rr) == 2:
                regs[rr[0]] = old.get(rr[1])
            elif op == 'new-instance' and len(rr) == 1 and type(ins.literal) is str:
                regs[rr[0]] = ('object', ins.offset)
                objects[ins.offset] = (ins.literal, None)
            elif op == 'new-array' and len(rr) == 2:
                regs.pop(rr[0], None)
                size = old.get(rr[1])
                if ins.literal == ARRAY and size and size[0] == 'int' and 1 <= size[1] <= 16:
                    regs[rr[0]] = ('array', ins.offset)
                    arrays[ins.offset] = [None] * size[1]
            elif op in ('filled-new-array', 'filled-new-array/range'):
                if ins.literal == ARRAY and 1 <= len(rr) <= 16:
                    arrays[ins.offset] = [(old.get(reg), ins.offset) for reg in rr]
                    pending = ('array', ins.offset)
            elif op == 'move-result-object' and len(rr) == 1:
                regs[rr[0]] = previous_pending
            elif op == 'aput-object' and len(rr) == 3:
                array = old.get(rr[1])
                if array and array[0] == 'array' and array[1] in arrays:
                    index = old.get(rr[2])
                    if index and index[0] == 'int' and 0 <= index[1] < len(arrays[array[1]]):
                        arrays[array[1]][index[1]] = (old.get(rr[0]), ins.offset)
                    else:
                        arrays.pop(array[1], None)
                else:
                    arrays.clear()
            elif op.startswith('invoke'):
                value = old.get(rr[0]) if rr else None
                obj = objects.get(value[1]) if value and value[0] == 'object' else None
                if (obj and obj[1] is None and len(rr) == 1 and op in ('invoke-direct', 'invoke-direct/range')
                        and ins.target == obj[0] + '-><init>()V'):
                    objects[value[1]] = (obj[0], ins.offset)
                    continue
                if ins.target == INIT and op in ('invoke-virtual', 'invoke-virtual/range') and len(rr) == 4:
                    array = old.get(rr[2])
                    elements = arrays.get(array[1], []) if array and array[0] == 'array' else []
                    for index, element in enumerate(elements):
                        ref = element[0] if element else None
                        obj = objects.get(ref[1]) if ref and ref[0] == 'object' else None
                        callback = candidates.get(obj[0]) if obj and obj[1] is not None else None
                        if not callback:
                            continue
                        multi = len(elements) > 1
                        findings.append(Finding('AOS-TLS-007' if multi else 'AOS-TLS-006',
                            'Permissive TrustManager reaches SSLContext initialization',
                            'A bounded TrustManager array contains a freshly constructed callback whose server-certificate '
                            'validation body is empty, and reaches SSLContext.init. Provider selection/acceptance, successful initialization, '
                            'socket use and runtime reachability remain unverified.',
                            'NETWORK', type='REVIEW' if multi else 'WEAKNESS', severity='MEDIUM', confidence='HIGH', analysis_level='L3',
                            location=Location(method.class_name, method.signature, ins.offset),
                            source=callback.location.method, sink=INIT,
                            data_flow=[dict(method=method.signature, offset=n, label=label) for n, label in
                                ((ref[1], 'callback allocation'), (obj[1], 'callback constructor'),
                                 (array[1], 'TrustManager array'), (element[1], 'array element assignment'),
                                 (ins.offset, 'SSLContext.init trust-manager argument'))],
                            related_methods=[callback.location.method, method.signature],
                            evidence=['Callback body finding: ' + callback.id, 'Array slot: ' + str(index)],
                            validation={'array_argument_connection': 'MODELED', 'runtime_initialization': 'UNKNOWN',
                                        'socket_use': 'UNKNOWN', 'provider_selection': 'UNKNOWN',
                                        'array_length': str(len(elements))}, standards={'cwe': ['CWE-295']},
                            recommendation='Verify context use and retain platform certificate validation; review callback and initialization evidence.'))
                # Unknown code can mutate aliases/arrays, so invalidate all object evidence.
                objects, arrays = {}, {}
            elif op != 'nop':
                regs, objects, arrays = {}, {}, {}
    return findings
