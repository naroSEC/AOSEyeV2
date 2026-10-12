"""Constant-argument checks scoped to individual basic blocks, never text grep."""
from analyzer.core.models import Finding, Location, Program
from analyzer.core.graph import DeclarationResolver
from analyzer.analyzers.crypto_parameters import parameter_context


def constant_context(program: Program) -> list[Finding]:
    findings = []
    resolver = DeclarationResolver(program)
    for method in program.methods.values():
        instructions = {i.offset: i for i in method.instructions}
        blocks = method.cfg or [{'offsets': [i.offset for i in method.instructions]}]
        for block in blocks:
            constants = {}
            for offset in block['offsets']:
                ins = instructions[offset]
                previous = dict(constants)
                for reg in ins.defs:
                    constants.pop(reg, None)
                if ins.opcode in ('const', 'const/4', 'const/16', 'const/high16', 'const-string', 'const-string/jumbo') and len(ins.registers) == 1:
                    constants[ins.registers[0]] = ins.literal
                elif ins.opcode in ('move', 'move/from16', 'move/16', 'move-object', 'move-object/from16', 'move-object/16') and len(ins.registers) == 2:
                    constants.pop(ins.registers[0], None)
                    if ins.registers[1] in previous:
                        constants[ins.registers[0]] = previous[ins.registers[1]]
                elif ins.opcode.startswith('invoke'):
                    # Signature matching includes owning class and parameter list boundary.
                    target = resolver.target(ins.target)
                    findings.extend(parameter_context(method, ins, target, previous))
                    arg = 0 if ins.opcode.startswith('invoke-static') else 1
                    value = previous.get(ins.registers[arg]) if len(ins.registers) > arg else None
                    rule_id = title = ''
                    category, severity = 'CRYPTO', 'LOW'
                    finding_type = 'WEAKNESS'
                    if target.startswith('Ljavax/crypto/Cipher;->getInstance(') and isinstance(value, str):
                        upper = value.upper()
                        if upper.split('/')[0] in {'DES', 'DESEDE', 'RC4', 'ARCFOUR'} or '/ECB/' in upper:
                            rule_id, title = 'AOS-CRYPTO-001', 'Explicit weak cipher configuration'
                            severity = 'MEDIUM'
                    elif target.startswith('Ljava/security/MessageDigest;->getInstance(') and isinstance(value, str):
                        if value.upper().replace('-', '') in {'MD5', 'SHA1'}:
                            rule_id, title = 'AOS-CRYPTO-002', 'Weak hash algorithm requires security-context review'
                            # Checksums, identifiers and protocol-mandated digests are
                            # not automatically security weaknesses.
                            finding_type, severity = 'REVIEW', 'INFO'
                    elif target.startswith('Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(') and value == 1:
                        rule_id, title = 'AOS-WEBVIEW-002', 'Universal access from file URLs enabled'
                        category, severity = 'WEBVIEW', 'MEDIUM'
                    elif target.startswith('Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(') and value == 1:
                        rule_id, title = 'AOS-WEBVIEW-003', 'WebView debugging explicitly enabled'
                        category = 'WEBVIEW'
                    if rule_id:
                        findings.append(Finding(rule_id, title,
                            'A constant argument is established within a DEX basic block. Review reachability and security relevance.',
                            category, type=finding_type, severity=severity, confidence='HIGH',
                            analysis_level='L2', location=Location(method.class_name, method.signature, ins.offset),
                            sink=target, evidence=[f'Constant argument: {value}', ins.text],
                            recommendation=('Determine whether the digest protects security-sensitive integrity or credentials; '
                                            'do not infer a vulnerability from an algorithm name alone.'
                                            if finding_type == 'REVIEW' else
                                            'Use a security-appropriate algorithm or disable permissive settings in production.')))
                elif ins.opcode != 'nop' and not ins.defs:
                    # Missing write metadata must not preserve an old constant
                    # across move-result, arithmetic, or other unknown writes.
                    constants.clear()
                # Without CFG, do not carry constants across a branch.
                if ins.opcode.startswith(('if-', 'goto', 'packed-switch', 'sparse-switch', 'return', 'throw')):
                    constants.clear()
    return findings
