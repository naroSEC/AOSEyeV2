"""Fresh callback object -> exact platform setter, in a complete linear body."""
from analyzer.core.models import Finding, Location
from analyzer.analyzers.tls import _linear

SETTERS = {
    'Ljavax/net/ssl/HttpsURLConnection;->setHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V':
        ('invoke-virtual', 2, 1, 'AOS-TLS-002', 'AOS-TLS-004'),
    'Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V':
        ('invoke-static', 1, 0, 'AOS-TLS-002', 'AOS-TLS-004'),
    'Landroid/webkit/WebView;->setWebViewClient(Landroid/webkit/WebViewClient;)V':
        ('invoke-virtual', 2, 1, 'AOS-TLS-003', 'AOS-TLS-005'),
}


def tls_installation(program, callbacks, cancel):
    # Exact allocation class only: do not jump over overriding declarations.
    candidates = {(f.location.class_name, f.rule_id): f for f in callbacks if f.type == 'WEAKNESS'}
    findings = []
    for method in program.methods.values():
        cancel.check()
        if not _linear(method):
            continue
        refs, objects = {}, {}
        for ins in method.instructions:
            cancel.check()
            op, rr = ins.opcode, ins.registers
            previous = dict(refs)
            for reg in ins.defs:
                refs.pop(reg, None)
            if op == 'new-instance' and len(rr) == 1 and type(ins.literal) is str:
                refs[rr[0]] = ins.offset
                objects[ins.offset] = (ins.literal, None)
            elif op in ('move-object', 'move-object/from16', 'move-object/16') and len(rr) == 2:
                refs.pop(rr[0], None)
                if rr[1] in previous:
                    refs[rr[0]] = previous[rr[1]]
            elif op.startswith('invoke'):
                identity = previous.get(rr[0]) if rr else None
                obj = objects.get(identity)
                if (obj and obj[1] is None and op in ('invoke-direct', 'invoke-direct/range')
                        and len(rr) == 1 and ins.target == obj[0] + '-><init>()V'):
                    objects[identity] = (obj[0], ins.offset)
                    continue
                setter = SETTERS.get(ins.target)
                if setter and op in (setter[0], setter[0] + '/range') and len(rr) == setter[1]:
                    identity = previous.get(rr[setter[2]])
                    obj = objects.get(identity)
                    callback = candidates.get((obj[0], setter[3])) if obj and obj[1] is not None else None
                    if callback:
                        finding = Finding(setter[4], 'Permissive TLS callback reaches a platform setter',
                            'A freshly constructed callback with a verified permissive body is passed to a platform setter. '
                            'This proves a bounded static argument connection, not successful registration, continued use, '
                            'network activity or exploitability. Later replacement and runtime reachability are unverified.',
                            'NETWORK', type='WEAKNESS', severity='MEDIUM', confidence='HIGH', analysis_level='L3',
                            location=Location(method.class_name, method.signature, ins.offset),
                            source=callback.location.method, sink=ins.target,
                            data_flow=[dict(method=method.signature, offset=identity, label='callback allocation'),
                                       dict(method=method.signature, offset=obj[1], label='callback constructor'),
                                       dict(method=method.signature, offset=ins.offset, label='platform setter argument')],
                            related_methods=[callback.location.method, method.signature],
                            evidence=['Callback body finding: ' + callback.id,
                                      'Callback body offset: ' + str(callback.location.offset)],
                            validation={'setter_argument_connection': 'MODELED', 'runtime_registration': 'UNKNOWN',
                                        'subsequent_replacement': 'UNKNOWN', 'network_execution': 'UNKNOWN'},
                            standards={'cwe': ['CWE-297' if setter[3] == 'AOS-TLS-002' else 'CWE-295']},
                            recommendation='Inspect both callback and setter evidence; retain platform validation and cancel SSL errors.')
                        findings.append(finding)
                # Do not retain objects that escape to arbitrary calls/setters.
                for reg in rr:
                    objects.pop(previous.get(reg), None)
            elif op in ('const', 'const/4', 'const/16', 'const/high16', 'const-string',
                        'const-string/jumbo', 'const-class', 'const-wide', 'const-wide/16',
                        'const-wide/32', 'const-wide/high16') and len(rr) == 1:
                refs.pop(rr[0], None)
                if op.startswith('const-wide'):
                    refs.pop(rr[0] + 1, None)
            elif op != 'nop':
                refs, objects = {}, {}
    return findings
