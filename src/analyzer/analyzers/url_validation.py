"""Bounded exact URI guards and static boolean helper summaries, not a safety verdict."""
from collections import deque
from analyzer.analyzers.exception_flow import exception_edges

PARSE = 'Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;'
PARTS = {'Landroid/net/Uri;->getScheme()Ljava/lang/String;': 'scheme',
         'Landroid/net/Uri;->getHost()Ljava/lang/String;': 'host'}
EQUALS = 'Ljava/lang/String;->equals(Ljava/lang/Object;)Z'
SINKS = {'Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V',
         'Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;Ljava/util/Map;)V'}


def url_guard_review(program, signature, observation, cancel=None, max_steps=4000, max_paths=128,
                     *, _initial=None, _stack=(), _budget=None):
    helper = observation is None
    budget = _budget if _budget is not None else [max_steps]
    report = dict(status='UNKNOWN', scheme_allowlist='UNKNOWN', host_allowlist='UNKNOWN',
                  method=signature, observation=observation, evidence=[], sink_paths=0, helper_calls=[],
                  exception_transitions=0,
                  scope='Bounded normal and conservative exception paths; at most two static String-to-boolean helper levels. '
                        'Every protected instruction may reach every listed handler, without type filtering; '
                        'pending results and guard facts are discarded on those edges. '
                        'No WebView parser equivalence, redirect or runtime safety proof. '
                        'Findings are not suppressed.')
    def unknown(reason):
        return dict(report, status='UNKNOWN', scheme_allowlist='UNKNOWN', host_allowlist='UNKNOWN',
                    evidence=[], reason=reason)
    method = program.methods.get(signature)
    if not method or not method.instructions:
        return unknown('Method body unavailable')
    if signature in _stack or len(_stack) > 2:
        return unknown('Helper recursion or depth limit')
    if method.diagnostics:
        return unknown('Method normalization diagnostics prevent a guard proof')
    instructions = method.instructions
    code = {i.offset: i for i in instructions}
    sink = code.get(observation)
    if not helper and (not sink or sink.target not in SINKS or len(sink.registers) < 2):
        return unknown('Unsupported sink; only exact WebView.loadUrl signatures are modeled')
    if len(instructions) > 2000 or len(code) != len(instructions):
        return unknown('Method size or duplicate offset limit')
    try:
        exceptional = exception_edges(method, code)
    except ValueError as exc:
        return unknown(str(exc))
    normal = {i.offset: i.normal_successors if i.normal_successors is not None else i.successors for i in instructions}
    if any(s not in code for successors in normal.values() for s in successors):
        return unknown('Unresolved normal CFG successor')
    if any(s not in code for i in instructions for s in i.successors):
        return unknown('Unresolved CFG successor')
    ordered = sorted(code)
    following = dict(zip(ordered, ordered[1:]))
    initial = _initial if _initial is not None else {r: ('value', signature, 'parameter', r) for r in method.parameter_registers}
    queue = deque([(ordered[0], initial, None, frozenset(), frozenset())])
    arrivals, returns = [], []
    while queue:
        if cancel:
            cancel.check()
        if budget[0] <= 0 or len(queue) + len(arrivals) + len(returns) > max_paths:
            return unknown('Path or instruction budget reached')
        offset, regs, pending, guards, visited = queue.popleft()
        if offset in visited:
            return unknown('Loop encountered; no bounded-loop proof is accepted')
        visited = visited | {offset}
        budget[0] -= 1
        ins = code[offset]
        rr, op = ins.registers, ins.opcode
        for handler in exceptional.get(offset, ()):
            queue.append((handler, dict(regs), None, frozenset(), visited))
            report['exception_transitions'] += 1
        if not helper and offset == observation:
            value = regs.get(rr[1])
            arrivals.append({g for g in guards if value is not None and g[1] == value})
            continue
        old, regs = regs, dict(regs)
        for reg in ins.defs:
            regs.pop(reg, None)
        result = None
        if op == 'move-exception' and rr:
            regs.pop(rr[0], None)
        elif op.startswith('move-result') and rr:
            regs.pop(rr[0], None)
            if pending is not None:
                regs[rr[0]] = pending
        elif op.startswith('move') and op != 'move-exception' and len(rr) == 2:
            regs.pop(rr[0], None)
            if rr[1] in old:
                regs[rr[0]] = old[rr[1]]
        elif op.startswith('const') and rr:
            regs.pop(rr[0], None)
            if op.startswith('const-string') and isinstance(ins.literal, str):
                regs[rr[0]] = ('constant', ins.literal)
            elif type(ins.literal) is int and ins.literal in (0, 1):
                regs[rr[0]] = ('boolean', ins.literal)
        elif op.startswith('invoke'):
            args = [old.get(r) for r in rr]
            result = ('value', signature, 'call', offset)
            if ins.target == PARSE and op.startswith('invoke-static') and len(args) == 1 and args[0] is not None:
                result = ('uri', args[0])
            elif (ins.target in PARTS and op.startswith('invoke-virtual') and len(args) == 1
                  and args[0] and args[0][0] == 'uri'):
                result = ('part', PARTS[ins.target], args[0][1])
            elif ins.target == EQUALS and op.startswith('invoke-virtual') and len(args) == 2:
                for part, constant in (args, args[::-1]):
                    if (part and constant and part[0] == 'part' and constant[0] == 'constant'
                            and constant[1]):
                        result = ('predicate', part[1], part[2], constant[1], offset)
                        break
            elif (op.startswith('invoke-static') and ins.target.endswith('(Ljava/lang/String;)Z')
                  and ins.target in program.methods and len(args) == 1 and args[0] is not None):
                callee = program.methods[ins.target]
                if len(callee.parameter_registers) == 1:
                    summary = url_guard_review(program, ins.target, None, cancel, max_steps, max_paths,
                        _initial={callee.parameter_registers[0]: args[0]},
                        _stack=_stack + (signature,), _budget=budget)
                    report['helper_calls'].append(dict(method=ins.target, call_offset=offset,
                        status=summary['status'], reason=summary.get('reason', ''),
                        exception_transitions=summary['exception_transitions'], nested=summary['helper_calls']))
                    report['exception_transitions'] += summary['exception_transitions']
                    if summary['status'] == 'BOOLEAN_SUMMARY':
                        result = ('helper-predicate', summary['_true_guards'])
        elif op == 'check-cast' and rr and rr[0] in old:
            regs[rr[0]] = old[rr[0]]
        if op in ('if-eqz', 'if-nez') and len(rr) == 1:
            predicate = old.get(rr[0])
            if predicate and predicate[0] in ('predicate', 'helper-predicate'):
                fallthrough = following.get(offset)
                if len(set(normal[offset])) != 2 or fallthrough not in normal[offset]:
                    return unknown('Cannot distinguish branch target from physical fallthrough')
                taken = next(s for s in normal[offset] if s != fallthrough)
                accepted = fallthrough if op == 'if-eqz' else taken
                for successor in normal[offset]:
                    constraints = ({(predicate[1], predicate[2], predicate[3], predicate[4], offset, accepted, signature)}
                                   if predicate[0] == 'predicate' else predicate[1])
                    next_guards = guards | constraints if successor == accepted else guards
                    queue.append((successor, dict(regs), None, next_guards, visited))
                continue
        if op.startswith(('return', 'throw')):
            if helper and op.startswith('return'):
                value = old.get(rr[0]) if rr else None
                if value and value[0] == 'boolean':
                    if value[1] == 1:
                        returns.append(guards)
                elif value and value[0] == 'predicate':
                    returns.append(guards | {(value[1], value[2], value[3], value[4], offset, offset, signature)})
                elif value and value[0] == 'helper-predicate':
                    returns.append(guards | value[1])
                else:
                    return unknown('Helper return value is not a modeled boolean')
            continue
        if not normal[offset]:
            return unknown('Nonterminal instruction without a CFG successor')
        for successor in normal[offset]:
            queue.append((successor, dict(regs), result, guards, visited))
    if helper:
        if not returns:
            return unknown('No modeled true return')
        shared = frozenset.intersection(*(frozenset(path) for path in returns))
        if not shared:
            return unknown('A true return can bypass all modeled comparisons')
        return dict(report, status='BOOLEAN_SUMMARY', _true_guards=shared)
    if not arrivals:
        return unknown('No normalized normal-flow path to observation')
    report['sink_paths'] = len(arrivals)
    for kind in ('scheme', 'host'):
        if all(any(g[0] == kind for g in path) for path in arrivals):
            report[kind + '_allowlist'] = 'MODELED_EXACT_MATCH'
            evidence = {g for path in arrivals for g in path if g[0] == kind}
            report['evidence'].extend(dict(component=g[0], allowed_literal=g[2], equality_offset=g[3],
                                           branch_offset=g[4], accepting_successor=g[5], method=g[6],
                                           proof_kind='TRUE_RETURN_IMPLIES_EQUALITY' if g[4] == g[5]
                                           else 'EQUALITY_ACCEPTING_BRANCH')
                                      for g in sorted(evidence, key=repr))
    if report['evidence']:
        report['status'] = 'EXCEPTION_FLOW_CONSTRAINED' if report['exception_transitions'] else 'NORMAL_FLOW_CONSTRAINED'
    return report
