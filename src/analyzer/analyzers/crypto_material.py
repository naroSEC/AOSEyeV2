"""Block-local constant-string bytes -> copied key/IV spec -> Cipher.init.

No material values are retained in findings. Unknown mutations invalidate state.
"""
from analyzer.core.models import Finding, Location

KEY = 'Ljavax/crypto/spec/SecretKeySpec;'
IV = 'Ljavax/crypto/spec/IvParameterSpec;'
GCM = 'Ljavax/crypto/spec/GCMParameterSpec;'
PBE = 'Ljavax/crypto/spec/PBEKeySpec;'
DERIVE = 'Ljavax/crypto/SecretKeyFactory;->generateSecret(Ljava/security/spec/KeySpec;)Ljavax/crypto/SecretKey;'
CONSTRUCTORS = {
    KEY + '-><init>([BLjava/lang/String;)V': (3, KEY, 1),
    IV + '-><init>([B)V': (2, IV, 1),
    GCM + '-><init>(I[B)V': (3, GCM, 2),
    PBE + '-><init>([C[BI)V': (4, PBE, 2),
    PBE + '-><init>([C[BII)V': (5, PBE, 2),
}
INIT = {
    'Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V': 3,
    'Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V': 4,
    'Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)V': 5,
}
BYTES = {'Ljava/lang/String;->getBytes()[B': 1,
         'Ljava/lang/String;->getBytes(Ljava/lang/String;)[B': 2}
BASE64 = 'Landroid/util/Base64;->decode(Ljava/lang/String;I)[B'


def crypto_material(program, cancel):
    findings = {}
    for method in program.methods.values():
        cancel.check()
        code = {i.offset: i for i in method.instructions}
        for block in method.cfg or [{'offsets': list(code)}]:
            regs, objects, pending = {}, {}, None
            for offset in block['offsets']:
                cancel.check()
                ins = code[offset]
                op, rr = ins.opcode, ins.registers
                old = dict(regs)
                previous_pending, pending = pending, None
                for reg in ins.defs:
                    regs.pop(reg, None)
                if op in ('const-string', 'const-string/jumbo') and len(rr) == 1:
                    regs[rr[0]] = ('text', (offset,)) if isinstance(ins.literal, str) else None
                elif op in ('const', 'const/4', 'const/16', 'const/high16') and len(rr) == 1:
                    regs[rr[0]] = ('int', ins.literal) if type(ins.literal) is int else None
                elif op == 'new-instance' and len(rr) == 1:
                    regs[rr[0]] = ('ref', offset)
                    objects[offset] = (ins.literal, ())
                elif op in ('move-object', 'move-object/from16', 'move-object/16', 'move', 'move/from16', 'move/16') and len(rr) == 2:
                    regs[rr[0]] = old.get(rr[1])
                elif op == 'move-result-object' and len(rr) == 1:
                    regs[rr[0]] = previous_pending
                elif op.startswith('invoke'):
                    values = [old.get(r) for r in rr]
                    target = ins.target
                    if (target in BYTES and op in ('invoke-virtual', 'invoke-virtual/range')
                            and len(rr) == BYTES[target] and values[0] and values[0][0] == 'text'
                            and (len(rr) == 1 or values[1] and values[1][0] == 'text')):
                        pending = ('bytes', values[0][1] + (offset,))
                    elif (target == BASE64 and op in ('invoke-static', 'invoke-static/range')
                            and len(rr) == 2 and values[0] and values[0][0] == 'text'
                            and values[1] and values[1][0] == 'int' and 0 <= values[1][1] <= 31):
                        # Conditional on decode returning; do not decode/store secret material here.
                        pending = ('bytes', values[0][1] + (offset,))
                    elif target in CONSTRUCTORS and op in ('invoke-direct', 'invoke-direct/range'):
                        count, kind, slot = CONSTRUCTORS[target]
                        if values and values[0] and values[0][0] == 'ref':
                            identity = values[0][1]
                            initial = objects.pop(identity, None)
                            material = values[slot] if len(rr) == count else None
                            if initial and initial[0] == kind and material and material[0] == 'bytes':
                                objects[identity] = (kind, material[1] + (offset,))
                    elif target == DERIVE and op in ('invoke-virtual', 'invoke-virtual/range') and len(rr) == 2:
                        value = values[1]
                        obj = objects.get(value[1]) if value and value[0] == 'ref' else None
                        if obj and obj[0] == PBE and obj[1]:
                            f = Finding('AOS-CRYPTO-007', 'Constant-derived salt reaches key derivation',
                                'A constant string supplies bytes copied into PBEKeySpec and passed to generateSecret. '
                                'Password entropy, selected KDF, parameter validity and runtime execution remain unverified.',
                                'CRYPTO', type='REVIEW', severity='LOW', confidence='HIGH', analysis_level='L3',
                                location=Location(method.class_name, method.signature, offset),
                                source='constant string (redacted)', sink=target,
                                data_flow=[dict(method=method.signature, offset=n, label=label) for n, label in
                                           zip(obj[1] + (offset,), ('constant string (redacted)', 'string-to-bytes',
                                                                   'PBEKeySpec salt argument', 'generateSecret argument'))],
                                evidence=['Salt values omitted; block-local DEX source and consumer linked'],
                                validation={'runtime_execution': 'UNKNOWN', 'algorithm_suitability': 'UNKNOWN'},
                                recommendation='Review KDF use and generate an appropriate unique salt for each password-derived key.',
                                standards={'cwe': ['CWE-760']})
                            findings[f.id] = f
                    elif target in INIT and op in ('invoke-virtual', 'invoke-virtual/range') and len(rr) == INIT[target]:
                        mode = values[1]
                        if mode in (('int', 1), ('int', 2)):
                            for slot, kinds, rule, title in (
                                (2, (KEY,), 'AOS-CRYPTO-005', 'Constant-derived key reaches Cipher.init'),
                                (3, (IV, GCM), 'AOS-CRYPTO-006', 'Constant-derived IV reaches encryption initialization')):
                                if slot >= len(values) or slot == 3 and mode != ('int', 1):
                                    continue
                                value = values[slot]
                                obj = objects.get(value[1]) if value and value[0] == 'ref' else None
                                if not obj or obj[0] not in kinds or not obj[1]:
                                    continue
                                path = [dict(method=method.signature, offset=n, label=label) for n, label in
                                        zip(obj[1] + (offset,), ('constant string (redacted)', 'string-to-bytes',
                                                               'parameter constructor', 'Cipher.init argument'))]
                                f = Finding(rule, title,
                                    'A block-local DEX path connects a constant string through bytes and a copied parameter object '
                                    'to Cipher.init. Provider acceptance, key/IV size, runtime execution and algorithm suitability are unverified.',
                                    'CRYPTO', type='REVIEW', severity='MEDIUM', confidence='HIGH', analysis_level='L3',
                                    location=Location(method.class_name, method.signature, offset),
                                    source='constant string (redacted)', sink=target, data_flow=path,
                                    evidence=['Material values omitted; exact DEX constructor and consumer arguments linked'],
                                    validation={'runtime_execution': 'UNKNOWN', 'algorithm_suitability': 'UNKNOWN'},
                                    recommendation='Verify actual encryption use; avoid embedded production keys and use mode-appropriate IV generation.',
                                    standards={'cwe': ['CWE-321'] if slot == 2 else []})
                                findings[f.id] = f
                    else:
                        # Calls can mutate passed arrays or tracked objects. Copy
                        # constructors already retain independent provenance.
                        for value in values:
                            if value and value[0] == 'ref':
                                objects.pop(value[1], None)
                            elif value and value[0] == 'bytes':
                                regs = {r: v for r, v in regs.items() if v != value}
                elif op != 'nop':
                    # Unsupported writes/branches and array stores cannot leave
                    # stale provenance usable by a later crypto consumer.
                    regs, objects = {}, {}
    return list(findings.values())
