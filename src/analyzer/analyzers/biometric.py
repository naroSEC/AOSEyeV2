"""Direct failure/error -> success(null) callback calls; no bypass assertion."""
from analyzer.analyzers.tls import _linear, _implements
from analyzer.core.models import Finding, Location

FAMILIES = ('Landroid/hardware/biometrics/BiometricPrompt', 'Landroidx/biometric/BiometricPrompt')
FAILURES = {'onAuthenticationFailed()V': 1,
            'onAuthenticationError(ILjava/lang/CharSequence;)V': 3}


def biometric_context(program, cancel):
    findings = []
    for method in program.methods.values():
        cancel.check()
        name = method.signature.partition('->')[2]
        if (name not in FAILURES or len(method.parameter_registers) != FAILURES[name]
                or not _linear(method)):
            continue
        family = next((f for f in FAMILIES if _implements(program, method.class_name,
                                                         f + '$AuthenticationCallback;')), None)
        if not family:
            continue
        target = method.class_name + '->onAuthenticationSucceeded(' + family + '$AuthenticationResult;)V'
        # Exact local declaration only. Do not assume that a framework no-op or
        # an unindexed inherited override grants access.
        if target not in program.methods:
            continue
        code = [i for i in method.instructions if i.opcode != 'nop']
        if not code or code[-1].opcode != 'return-void':
            continue
        values = {method.parameter_registers[0]: 'this'}
        calls = []
        for ins in code[:-1]:
            cancel.check()
            rr = ins.registers
            old = dict(values)
            for register in ins.defs:
                values.pop(register, None)
            if ins.opcode in ('move-object', 'move-object/from16', 'move-object/16') and len(rr) == 2:
                values[rr[0]] = old.get(rr[1])
            elif ins.opcode in ('const/4', 'const/16', 'const', 'const/high16') and len(rr) == 1:
                values[rr[0]] = 'null' if type(ins.literal) is int and ins.literal == 0 else None
            elif (ins.opcode in ('invoke-virtual', 'invoke-virtual/range') and ins.target == target
                  and len(rr) == 2 and old.get(rr[0]) == 'this' and old.get(rr[1]) == 'null'):
                calls.append(ins)
            else:
                break
        else:
            for ins in calls:
                findings.append(Finding('AOS-AUTH-001', 'Biometric failure callback directly calls success with null',
                    'A complete straight-line failure/error callback calls its local success callback on this with a null result. '
                    'Callback installation, alternate authentication, privileged actions and server authorization are unverified. '
                    'The success handler may reject null or perform only UI work; this is not proof of authentication bypass.',
                    'AUTH', type='REVIEW', severity='MEDIUM', confidence='HIGH', analysis_level='L2',
                    location=Location(method.class_name, method.signature, ins.offset),
                    source=method.signature, sink=target, related_methods=[method.signature, target],
                    data_flow=[dict(method=method.signature, offset=ins.offset,
                                    label='direct success callback call with null authentication result')],
                    evidence=['Declared biometric callback ancestry and exact local success method',
                              'Failure/error body contains only constant/move operations and direct success calls'],
                    validation={'callback_installation': 'UNKNOWN', 'privileged_action': 'UNKNOWN',
                                'alternate_authentication': 'UNKNOWN', 'server_authorization': 'UNKNOWN'},
                    recommendation='Inspect success-handler null handling and protected actions; verify alternate authentication before granting access.'))
    return findings
