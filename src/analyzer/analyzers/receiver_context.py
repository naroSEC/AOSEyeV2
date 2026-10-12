"""Bounded same-receiver context for existing flow findings, never a runtime verdict."""
from collections import defaultdict
from analyzer.analyzers.tls import _linear

GET_SETTINGS = 'Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;'
ADD_BRIDGE = 'Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V'
REMOVE_BRIDGE = 'Landroid/webkit/WebView;->removeJavascriptInterface(Ljava/lang/String;)V'
WEB_SETTINGS = {f'Landroid/webkit/WebSettings;->{name}(Z)V': key for name, key in (
    ('setJavaScriptEnabled', 'javascript'), ('setAllowFileAccess', 'file_access'),
    ('setAllowContentAccess', 'content_access'),
    ('setAllowFileAccessFromFileURLs', 'file_url_access'),
    ('setAllowUniversalAccessFromFileURLs', 'universal_file_url_access'))}
WEB_LOADS = {
    'Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V': 2,
    'Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;Ljava/util/Map;)V': 3,
    'Landroid/webkit/WebView;->loadData(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V': 4,
    'Landroid/webkit/WebView;->loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V': 6,
    'Landroid/webkit/WebView;->evaluateJavascript(Ljava/lang/String;Landroid/webkit/ValueCallback;)V': 3}
EDITOR = 'Landroid/content/SharedPreferences$Editor;->'
PUT = EDITOR + 'putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;'
FLUSH = {EDITOR + 'apply()V', EDITOR + 'commit()Z'}
MOVES = {'move-object', 'move-object/from16', 'move-object/16', 'move', 'move/from16', 'move/16'}
CONSTS = {'const', 'const/4', 'const/16', 'const/high16'}


def annotate_receiver_context(program, findings, cancel):
    grouped = defaultdict(lambda: defaultdict(list))
    for finding in findings:
        if finding.rule_id in {'AOS-WEBVIEW-004', 'AOS-WEBVIEW-005', 'AOS-WEBVIEW-006', 'AOS-SENSITIVE-003'}:
            grouped[finding.location.method][finding.location.offset].append(finding)
            finding.validation['receiver_context'] = 'UNKNOWN'
    for signature, targets in grouped.items():
        cancel.check()
        method = program.methods.get(signature)
        if method is None or not _linear(method) or len(method.instructions) > 4000:
            continue
        refs = {r: ('parameter', r) for r in method.parameter_registers}
        constants, web, writes, bridges = {}, {}, {}, {}
        pending = None
        for ins in method.instructions:
            cancel.check()
            op, rr = ins.opcode, ins.registers
            old, ints, result = dict(refs), dict(constants), pending
            pending = None
            for reg in ins.defs:
                refs.pop(reg, None)
                constants.pop(reg, None)
            if op in MOVES and len(rr) == 2:
                refs.pop(rr[0], None)
                constants.pop(rr[0], None)
                if rr[1] in old:
                    refs[rr[0]] = old[rr[1]]
                if rr[1] in ints:
                    constants[rr[0]] = ints[rr[1]]
            elif op == 'move-result-object' and len(rr) == 1:
                refs.pop(rr[0], None)
                constants.pop(rr[0], None)
                if result is not None:
                    refs[rr[0]] = result
            elif op.startswith('const') and len(rr) == 1:
                refs.pop(rr[0], None)
                constants.pop(rr[0], None)
                if op in CONSTS and type(ins.literal) is int:
                    constants[rr[0]] = ins.literal
                elif op in ('const-string', 'const-string/jumbo') and isinstance(ins.literal, str):
                    constants[rr[0]] = ins.literal
                if op.startswith('const-wide'):
                    refs.pop(rr[0] + 1, None)
                    constants.pop(rr[0] + 1, None)
            elif op == 'new-instance' and len(rr) == 1:
                refs[rr[0]] = ('allocation', ins.offset)
                constants.pop(rr[0], None)
            elif op.startswith('invoke'):
                receiver = old.get(rr[0]) if rr else None
                virtual = op in ('invoke-virtual', 'invoke-virtual/range')
                interface = op in ('invoke-interface', 'invoke-interface/range')
                if virtual and ins.target == GET_SETTINGS and len(rr) == 1 and receiver is not None:
                    pending = ('settings', receiver)
                elif virtual and ins.target in WEB_SETTINGS and len(rr) == 2:
                    # Parameters/results may alias: any mutation invalidates facts for other identities.
                    state = web.get(receiver[1], {}).copy() if receiver and receiver[0] == 'settings' else {}
                    bridge_state = bridges.get(receiver[1], {}).copy() if receiver and receiver[0] == 'settings' else {}
                    bridges = {receiver[1]: bridge_state} if receiver and receiver[0] == 'settings' else {}
                    web, writes = {}, {}
                    if receiver and receiver[0] == 'settings':
                        value = ints.get(rr[1])
                        state[WEB_SETTINGS[ins.target]] = dict(value=('ENABLED' if value == 1 else
                            'DISABLED' if value == 0 else 'UNKNOWN'), offset=ins.offset)
                        web[receiver[1]] = state
                elif virtual and ins.target in (ADD_BRIDGE, REMOVE_BRIDGE):
                    count = 3 if ins.target == ADD_BRIDGE else 2
                    state = web.get(receiver, {}).copy()
                    bridge_state = bridges.get(receiver, {}).copy()
                    web, writes, bridges = {}, {}, {}
                    if receiver is not None and len(rr) == count:
                        name = ints.get(rr[-1])
                        if isinstance(name, str) and 0 < len(name) <= 256:
                            bridge_state.pop(name, None)
                            if ins.target == ADD_BRIDGE and rr[1] in old:
                                if len(bridge_state) < 32:
                                    bridge_state[name] = dict(add_offset=ins.offset, object_nonnull='UNKNOWN',
                                        exposed_methods='UNKNOWN', runtime_exposure='UNKNOWN')
                                else:
                                    # Unknown/unbounded registration effects cannot preserve a partial set.
                                    bridge_state = {}
                            web[receiver] = state
                            bridges[receiver] = bridge_state
                elif virtual and ins.target in WEB_LOADS and len(rr) == WEB_LOADS[ins.target] and receiver is not None:
                    state = web.get(receiver, {})
                    for finding in targets.get(ins.offset, []):
                        if not finding.rule_id.startswith('AOS-WEBVIEW-'):
                            continue
                        registrations = list(bridges.get(receiver, {}).values())
                        finding.review['webview_context'] = dict(status='MODELED' if state or registrations else 'UNKNOWN',
                            settings=state.copy(), method=signature, load_offset=ins.offset,
                            scope='Same receiver in a complete linear body; unobserved defaults, overrides, '
                                  'runtime execution, redirects and JavaScript interface exposure are unknown.')
                        if registrations:
                            finding.review['webview_context']['bridge_registrations'] = registrations
                            finding.validation['webview_bridge_registration'] = 'MODELED'
                            finding.validation['webview_bridge_runtime_exposure'] = 'UNKNOWN'
                        if state or registrations:
                            finding.validation['receiver_context'] = 'MODELED'
                            for key, value in state.items():
                                finding.validation['webview_' + key] = value['value']
                    # Loading may invoke application callbacks that change configuration.
                    web, writes, bridges = {}, {}, {}
                elif interface and ins.target == PUT and len(rr) == 3 and receiver is not None:
                    web, writes, bridges = {}, {}, {}
                    rows = [f for f in targets.get(ins.offset, []) if f.rule_id == 'AOS-SENSITIVE-003']
                    if rows:
                        writes[receiver] = rows
                    pending = receiver  # Android Editor fluent API contract, not an arbitrary method.
                elif interface and ins.target in FLUSH and len(rr) == 1 and receiver is not None:
                    for finding in writes.get(receiver, []):
                        finding.validation['receiver_context'] = 'MODELED'
                        finding.validation['editor_flush_call'] = 'MODELED'
                        finding.review['editor_context'] = dict(status='MODELED', method=signature,
                            write_offset=finding.location.offset, flush_offset=ins.offset, sink=ins.target,
                            scope='Same editor putString followed by apply/commit call. Return value, disk '
                                  'completion, implementation overrides, encryption and access remain unknown.')
                    web, writes, bridges = {}, {}, {}
                else:
                    web, writes, bridges = {}, {}, {}
                    pending = ('call_result', ins.offset)
            elif op != 'nop':
                # Unknown effects/field stores/array writes invalidate all contextual facts.
                refs, constants, web, writes, bridges = {}, {}, {}, {}, {}
