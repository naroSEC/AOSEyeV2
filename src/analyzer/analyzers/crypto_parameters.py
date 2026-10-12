"""Exact constructor/argument checks. Does not prove key derivation or cipher use."""
from analyzer.core.models import Finding, Location

PARAMETERS = {
    'Ljavax/crypto/spec/PBEKeySpec;-><init>([C[BI)V': (4, 3, 'iterations'),
    'Ljavax/crypto/spec/PBEKeySpec;-><init>([C[BII)V': (5, 3, 'iterations'),
    'Ljavax/crypto/spec/PBEParameterSpec;-><init>([BI)V': (3, 2, 'iterations'),
    'Ljavax/crypto/spec/PBEParameterSpec;-><init>([BILjava/security/spec/AlgorithmParameterSpec;)V': (4, 2, 'iterations'),
    'Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[B)V': (3, 1, 'tag_bits'),
    'Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[BII)V': (5, 1, 'tag_bits'),
}


def parameter_context(method, ins, target, constants):
    spec = PARAMETERS.get(target)
    if spec is None or ins.opcode not in ('invoke-direct', 'invoke-direct/range'):
        return []
    count, argument, kind = spec
    if len(ins.registers) != count:
        return []
    value = constants.get(ins.registers[argument])
    if type(value) is not int:
        return []
    if kind == 'iterations' and value == 1:
        rule, title = 'AOS-CRYPTO-003', 'Single-iteration password-based parameter configuration'
        detail = 'A single iteration is requested; review the selected KDF, password entropy and work factor.'
        cwe = 'CWE-916'
    elif kind == 'tag_bits' and value in (32, 64):
        rule, title = 'AOS-CRYPTO-004', 'Short GCM authentication tag requires protocol review'
        detail = '32/64-bit tags have application-specific constraints; verify protocol requirements and forgery limits.'
        cwe = 'CWE-326'
    else:
        return []
    return [Finding(rule, title,
        'An exact constructor argument is constant within a DEX basic block. ' + detail +
        ' Object construction, provider acceptance, use in key derivation/Cipher.init and runtime reachability are not proved.',
        'CRYPTO', type='REVIEW', severity='LOW', confidence='HIGH', analysis_level='L2',
        location=Location(method.class_name, method.signature, ins.offset), sink=target,
        evidence=[f'{kind}: {value}', f'{ins.offset:04x}  {ins.opcode} {target}'],
        validation={'runtime_use': 'UNKNOWN', 'algorithm_or_protocol': 'UNKNOWN'},
        recommendation='Trace the parameter object to its cryptographic consumer and review algorithm/protocol-specific requirements.',
        standards={'cwe': [cwe]})]
