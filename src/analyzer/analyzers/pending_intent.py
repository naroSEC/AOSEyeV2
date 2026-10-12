"""Block-local PendingIntent flags plus known Intent destination constraints."""
from analyzer.core.models import Finding, Location

INTENT = 'Landroid/content/Intent;'
PREFIX = 'Landroid/app/PendingIntent;->'
ARGS = '(Landroid/content/Context;ILandroid/content/Intent;I)'
CALLS = {PREFIX + name + ARGS + 'Landroid/app/PendingIntent;': 4
         for name in ('getActivity', 'getBroadcast', 'getService', 'getForegroundService')}
CALLS[PREFIX + 'getActivity(Landroid/content/Context;ILandroid/content/Intent;ILandroid/os/Bundle;)Landroid/app/PendingIntent;'] = 5
MUTABLE, IMMUTABLE, UNSAFE, NO_CREATE = 0x02000000, 0x04000000, 0x01000000, 0x20000000
CLASS_SETTERS = {
    INTENT + '->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;': ('class', (2,)),
    INTENT + '->setClassName(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;': ('string', (2,)),
    INTENT + '->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;': ('string', (1, 2)),
}


def known_name(value, kind):
    return bool(value and value[0] == kind and isinstance(value[1], str) and value[1])


def pending_intent_context(program, manifest, cancel):
    findings = {}
    sdk = manifest.get('target_sdk')
    for method in program.methods.values():
        cancel.check()
        code = {i.offset: i for i in method.instructions}
        for block in method.cfg or [{'offsets': list(code)}]:
            regs, intents, pending = {}, {}, None
            for offset in block['offsets']:
                cancel.check()
                ins = code[offset]
                op, rr, target = ins.opcode, ins.registers, ins.target
                old, prior_pending, pending = dict(regs), pending, None
                for r in ins.defs:
                    regs.pop(r, None)
                if op in ('const', 'const/4', 'const/16', 'const/high16') and len(rr) == 1:
                    regs[rr[0]] = ('int', ins.literal) if type(ins.literal) is int else None
                elif op in ('const-string', 'const-string/jumbo', 'const-class') and len(rr) == 1:
                    regs[rr[0]] = ('class' if op == 'const-class' else 'string', ins.literal)
                elif op == 'new-instance' and len(rr) == 1:
                    regs[rr[0]] = ('intent', offset) if ins.literal == INTENT else None
                elif op in ('move', 'move/from16', 'move/16', 'move-object', 'move-object/from16', 'move-object/16') and len(rr) == 2:
                    regs[rr[0]] = old.get(rr[1])
                elif op == 'move-result-object' and len(rr) == 1:
                    regs[rr[0]] = prior_pending
                elif op.startswith('invoke'):
                    values = [old.get(r) for r in rr]
                    ref = values[0] if values and values[0] and values[0][0] == 'intent' else None
                    if target in CALLS and op in ('invoke-static', 'invoke-static/range') and len(rr) == CALLS[target]:
                        flags = values[3][1] if values[3] and values[3][0] == 'int' else None
                        if type(flags) is not int or not -2147483648 <= flags <= 2147483647:
                            continue
                        flags &= 0xffffffff
                        value = values[2]
                        state = intents.get(value[1]) if value and value[0] == 'intent' else None
                        conflict = bool(flags & MUTABLE and flags & IMMUTABLE)
                        unconstrained = state == (False, False)
                        if not conflict and not (flags & MUTABLE and not flags & IMMUTABLE and not flags & NO_CREATE and unconstrained):
                            continue
                        rule = 'AOS-IPC-006' if conflict else 'AOS-IPC-005'
                        platform = ('INVALID_MUTABILITY_COMBINATION' if conflict else
                                    'UNSAFE_IMPLICIT_FLAG_PRESENT' if flags & UNSAFE else
                                    'MAY_REJECT_ON_API_34_PLUS' if type(sdk) is int and sdk >= 34 else 'UNKNOWN')
                        f = Finding(rule, 'Conflicting PendingIntent mutability flags' if conflict else
                            'Mutable PendingIntent with an unconstrained Intent',
                            'Constant flags and block-local Intent state were inspected. '
                            'Both mutability flags are set.' if conflict else
                            'A mutable PendingIntent request uses a locally constructed Intent without component or package restriction. '
                            'Platform rejection, existing-token reuse, delivery, attacker access and exploitability are not established.',
                            'IPC', type='REVIEW', severity='INFO' if conflict else 'MEDIUM', confidence='HIGH',
                            analysis_level='L2', location=Location(method.class_name, method.signature, offset), sink=target,
                            evidence=[f'flags=0x{flags:08x}', 'Destination state: ' + ('UNCONSTRAINED' if unconstrained else 'UNKNOWN_OR_CONSTRAINED')],
                            validation={'platform_behavior': platform, 'runtime_delivery': 'UNKNOWN', 'attacker_access': 'UNKNOWN'},
                            recommendation='Use immutable PendingIntents when possible; otherwise constrain the destination and verify runtime requirements.')
                        findings[f.id] = f
                    elif ref and target in (INTENT + '-><init>()V', INTENT + '-><init>(Ljava/lang/String;)V') and op in ('invoke-direct', 'invoke-direct/range'):
                        intents.pop(ref[1], None)
                        if len(rr) == (1 if target.endswith('()V') else 2):
                            intents[ref[1]] = (False, False)
                    elif ref and target == INTENT + '-><init>(Landroid/content/Context;Ljava/lang/Class;)V' and op in ('invoke-direct', 'invoke-direct/range'):
                        intents.pop(ref[1], None)
                        if len(rr) == 3 and known_name(values[2], 'class'):
                            intents[ref[1]] = (True, False)
                    elif ref and target == INTENT + '-><init>(Landroid/content/Intent;)V' and op in ('invoke-direct', 'invoke-direct/range'):
                        source = values[1] if len(rr) == 2 else None
                        state = intents.get(source[1]) if source and source[0] == 'intent' and source != ref else None
                        intents.pop(ref[1], None)
                        if state is not None:
                            intents[ref[1]] = state  # Immutable state; subsequent mutations are independent.
                    elif ref and ref[1] in intents and target in CLASS_SETTERS and op in ('invoke-virtual', 'invoke-virtual/range'):
                        _, package = intents.pop(ref[1])
                        kind, slots = CLASS_SETTERS[target]
                        if len(rr) == 3 and all(known_name(values[n], kind) for n in slots):
                            intents[ref[1]] = (True, package)
                        pending = ref
                    elif ref and ref[1] in intents and target == INTENT + '->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;' and op in ('invoke-virtual', 'invoke-virtual/range'):
                        _, package = intents.pop(ref[1])
                        if len(rr) == 2 and values[1] == ('int', 0):
                            intents[ref[1]] = (False, package)
                        pending = ref
                    elif ref and ref[1] in intents and op in ('invoke-virtual', 'invoke-virtual/range') and target == INTENT + '->setPackage(Ljava/lang/String;)Landroid/content/Intent;' and len(rr) == 2:
                        component, _ = intents.pop(ref[1])
                        if values[1] == ('int', 0):
                            intents[ref[1]] = (component, False)
                        elif values[1] and values[1][0] == 'string' and isinstance(values[1][1], str) and values[1][1]:
                            intents[ref[1]] = (component, True)
                        pending = ref
                    elif ref and ref[1] in intents and op in ('invoke-virtual', 'invoke-virtual/range') and target == INTENT + '->setAction(Ljava/lang/String;)Landroid/content/Intent;' and len(rr) == 2:
                        pending = ref
                    else:
                        for value in values:
                            if value and value[0] == 'intent':
                                intents.pop(value[1], None)
                elif op != 'nop':
                    regs, intents = {}, {}
    return list(findings.values())
