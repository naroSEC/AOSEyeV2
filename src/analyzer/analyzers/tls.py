"""Bounded TLS callback body checks, not proof of installation or exploitation.

Signature-only matches remain REVIEW findings when interface declarations are
missing. Verified interface ancestry still does not prove callback installation.
"""
from analyzer.core.models import Finding, Location

HOST = 'verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z'
TRUST = 'checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V'
SSL = 'onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V'
PROCEED = 'Landroid/webkit/SslErrorHandler;->proceed()V'
INTERFACES = {HOST: 'Ljavax/net/ssl/HostnameVerifier;', TRUST: 'Ljavax/net/ssl/X509TrustManager;'}


def _implements(program, owner, target):
    pending, seen = [owner], set()
    while pending and len(seen) < 256:
        current = pending.pop()
        if current == target:
            return True
        if current in seen:
            continue
        seen.add(current)
        parent = program.class_hierarchy.get(current)
        if parent:
            pending.append(parent)
        pending.extend(program.class_interfaces.get(current, []))
    return False


def _linear(method):
    code = method.instructions
    if not code or method.diagnostics or method.exception_regions or method.exception_status != 'NONE':
        return False
    if len({i.offset for i in code}) != len(code) or code != sorted(code, key=lambda i: i.offset):
        return False
    for n, ins in enumerate(code):
        expected = [code[n + 1].offset] if n + 1 < len(code) else []
        if ins.successors != expected or (ins.normal_successors is not None and ins.normal_successors != expected):
            return False
    return True


def _webview_client(program, owner):
    seen = set()
    while owner and owner not in seen:
        if owner == 'Landroid/webkit/WebViewClient;':
            return True
        seen.add(owner)
        owner = program.class_hierarchy.get(owner)
    return False


def tls_context(program, cancel=None):
    findings = []
    for method in program.methods.values():
        if cancel:
            cancel.check()
        name = method.signature.partition('->')[2]
        if name not in (HOST, TRUST, SSL) or not _linear(method):
            continue
        code = [i for i in method.instructions if i.opcode != 'nop']
        if not code:
            continue
        rule = title = ''
        kind, severity, cwe = 'REVIEW', 'INFO', 'CWE-295'
        if name == TRUST and len(code) == 1 and code[0].opcode == 'return-void':
            rule, title = 'AOS-TLS-001', 'Certificate-validation callback candidate does no validation'
        elif name == HOST:
            values = {}
            for ins in code[:-1]:
                rr = ins.registers
                if ins.opcode in ('const/4', 'const/16', 'const', 'const/high16') and len(rr) == 1 and type(ins.literal) is int:
                    values[rr[0]] = ins.literal
                elif ins.opcode in ('move', 'move/from16', 'move/16') and len(rr) == 2:
                    value = values.get(rr[1])
                    values.pop(rr[0], None)
                    if value is not None:
                        values[rr[0]] = value
                else:
                    break
            else:
                last = code[-1]
                if last.opcode == 'return' and len(last.registers) == 1 and values.get(last.registers[0]) == 1:
                    rule, title = 'AOS-TLS-002', 'Hostname-verification callback candidate always returns true'
                    cwe = 'CWE-297'
        elif name == SSL and _webview_client(program, method.class_name):
            # Only a direct, unconditional call on the incoming handler (or an
            # object-register alias) is promoted beyond API presence.
            params = method.parameter_registers
            if len(params) != 4:
                continue
            aliases, calls = {params[2]}, []
            for ins in code[:-1]:
                rr = ins.registers
                if ins.opcode in ('move-object', 'move-object/from16', 'move-object/16') and len(rr) == 2:
                    source = rr[1] in aliases
                    aliases.discard(rr[0])
                    if source:
                        aliases.add(rr[0])
                elif ins.opcode in ('invoke-virtual', 'invoke-virtual/range') and ins.target == PROCEED and len(rr) == 1 and rr[0] in aliases:
                    calls.append(ins)
                else:
                    break
            else:
                if calls and code[-1].opcode == 'return-void':
                    rule, title = 'AOS-TLS-003', 'WebView SSL-error callback unconditionally proceeds'
                    kind, severity = 'WEAKNESS', 'MEDIUM'
        if rule:
            verified_interface = name in INTERFACES and _implements(program, method.class_name, INTERFACES[name])
            if verified_interface:
                kind, severity = 'WEAKNESS', 'MEDIUM'
                title = title.replace('callback candidate', 'callback')
            evidence = [f'{i.offset:04x}  {i.text or i.opcode}' for i in code]
            findings.append(Finding(rule, title,
                'A bounded straight-line DEX callback body matches this pattern. '
                'Callback registration, runtime reachability and exploitability are not established. '
                + ('Declared interface ancestry matches ' + INTERFACES[name] + '; callback installation is not verified.'
                   if verified_interface else
                   ('Interface implementation is not verified; matching signatures alone do not prove a TLS callback.'
                    if kind == 'REVIEW' else 'The incoming SSL-error handler is used directly or through a register alias.')),
                'NETWORK', type=kind, severity=severity, confidence='HIGH', analysis_level='L2',
                location=Location(method.class_name, method.signature, calls[0].offset if name == SSL else code[-1].offset),
                sink=PROCEED if name == SSL else method.signature,
                evidence=evidence, bytecode='\n'.join(evidence), standards={'CWE': [cwe]},
                recommendation='Verify callback installation and use platform certificate/hostname validation; cancel WebView SSL errors.'))
    return findings
