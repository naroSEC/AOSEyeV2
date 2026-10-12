"""Ignored signature-verification results in constant-true methods, not an auth bypass proof."""
from analyzer.analyzers.tls import _linear
from analyzer.core.models import Finding, Location

VERIFY = {'Ljava/security/Signature;->verify([B)Z': 2,
          'Ljava/security/Signature;->verify([BII)Z': 4}


def authentication_verification(program, cancel):
    findings = []
    for method in program.methods.values():
        cancel.check()
        if (not method.signature.endswith(')Z') or len(method.instructions) > 4000 or
                not _linear(method)):
            continue
        code = [i for i in method.instructions if i.opcode != 'nop']
        if not code or code[-1].opcode != 'return' or len(code[-1].registers) != 1:
            continue
        constants, discarded = {}, []
        for index, ins in enumerate(code):
            cancel.check()
            rr, op = ins.registers, ins.opcode
            old = dict(constants)
            for reg in ins.defs:
                constants.pop(reg, None)
            if op in ('const', 'const/4', 'const/16', 'const/high16') and len(rr) == 1:
                constants[rr[0]] = ins.literal if type(ins.literal) is int else None
            elif op in ('move', 'move/from16', 'move/16') and len(rr) == 2:
                constants[rr[0]] = old.get(rr[1])
            elif op.startswith('invoke'):
                if (op in ('invoke-virtual', 'invoke-virtual/range') and ins.target in VERIFY and
                        len(rr) == VERIFY[ins.target] and index + 1 < len(code) and
                        not code[index + 1].opcode.startswith('move-result')):
                    discarded.append(ins)
            elif op == 'return':
                if len(rr) != 1 or old.get(rr[0]) != 1:
                    discarded = []
            else:
                # Missing write metadata, wide writes and unsupported arithmetic cannot preserve true.
                constants.clear()
        for ins in discarded:
            findings.append(Finding('AOS-AUTH-002', 'Signature verification result discarded before constant true return',
                'The normal linear path calls Signature.verify without consuming its boolean result and returns true. '
                'Exceptions may prevent returning. Whether this method authorizes an action, validates a token, or '
                'is only diagnostic code is unknown; this is not proof of authentication bypass.',
                'AUTH', type='REVIEW', severity='MEDIUM', confidence='HIGH', analysis_level='L2',
                location=Location(method.class_name, method.signature, ins.offset), source=ins.target,
                sink=method.signature,
                data_flow=[dict(method=method.signature, offset=ins.offset, label='discarded verification result'),
                           dict(method=method.signature, offset=code[-1].offset, label='normal-path constant true return')],
                validation={'verification_result_use': 'DISCARDED', 'normal_return': 'CONSTANT_TRUE',
                            'authorization_role': 'UNKNOWN', 'runtime_execution': 'UNKNOWN',
                            'server_authorization': 'UNKNOWN'},
                recommendation='Inspect callers and protected actions. Propagate or enforce verification failure before granting access.',
                standards={'cwe': ['CWE-252']}))
    return findings
