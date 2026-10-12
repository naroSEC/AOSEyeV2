"""Bounded, context-sensitive DEX path exploration; no decompiler-text matching."""
from dataclasses import dataclass, replace
from collections import deque
import re
from analyzer.app.jobs import Cancellation
from analyzer.core.models import Finding, Location, Program
from analyzer.core.rules.registry import RuleRegistry
from analyzer.core.rules.conditions import evaluate as evaluate_conditions
from analyzer.core.graph import DeclarationResolver
from analyzer.core.objectflow import Memory, ObjectValue, ClassConstant, tracked_type, intent_call, ASYNC_CALLS, ICC_CALLS, ICC_COMPONENT_KIND


@dataclass(frozen=True)
class Trace:
    source: str
    steps: tuple[tuple[str, int, str], ...]
    external: bool = False
    uncertain: bool = False

    def step(self, method, offset, label, uncertain=False):
        return replace(self, steps=self.steps + ((method, offset, label),),
                       uncertain=self.uncertain or uncertain)


class FlowEngine:
    def __init__(self, rules: RuleRegistry, max_steps=100000, max_depth=8):
        self.rules = rules.config
        self.transfers = {signature: rule for rule in self.rules['transfers']
                          for signature in rule['signatures']}
        self.max_steps, self.max_depth = max_steps, max_depth
        self.findings: dict[str, Finding] = {}
        self.diagnostics: set[str] = set()
        self.steps = 0

    def analyze(self, program: Program, entries: set[str], cancel: Cancellation, manifest=None, uncertain_entries=(),
                include_boundary_roots=True):
        self.program, self.cancel = program, cancel
        self.resolver = DeclarationResolver(program)
        self.uncertain_entries = set(uncertain_entries)
        self.manifest = manifest or {}
        self.boundaries = {}
        self.findings, self.diagnostics, self.steps = {}, set(), 0
        # Compute where a modeled source can occur. A call with no tainted input,
        # no tainted heap and no reachable source cannot create taint in this model.
        callers = {}
        direct_sources = set()
        boundary_roots = set()
        for sig, method in program.methods.items():
            cancel.check()
            for ins in method.instructions:
                if not ins.opcode.startswith('invoke'):
                    continue
                target = self.resolver.target(ins.target)
                if any(target.startswith(s) for s in self.rules['sources']):
                    direct_sources.add(sig)
                if include_boundary_roots and target in ASYNC_CALLS | ICC_CALLS:
                    boundary_roots.add(sig)
                if target in program.methods:
                    callers.setdefault(target, set()).add(sig)
        self.source_reachable = set(direct_sources)
        pending = list(direct_sources)
        while pending:
            callee = pending.pop()
            for caller in callers.get(callee, ()):
                if caller not in self.source_reachable:
                    self.source_reachable.add(caller)
                    pending.append(caller)
        primary = (sorted(entries) + sorted(direct_sources - entries) +
                 sorted(self.source_reachable - entries - direct_sources))
        primary_set = set(primary)
        roots = primary + sorted(boundary_roots - primary_set)
        self.source_reachable.update(boundary_roots)
        per_root = min(5000, max(200, self.max_steps // max(1, len(primary))))
        self.stats = dict(candidate_roots=len(roots), explored_roots=0, steps=0,
                          primary_candidate_roots=len(primary), primary_explored_roots=0,
                          per_root_budget=per_root, boundary_root_budget=200, skipped_untainted_calls=0,
                          required_condition_observations={'MET': 0, 'NOT_MET': 0, 'UNKNOWN': 0})
        for sig in roots:
            cancel.check()
            self.stats['explored_roots'] += 1
            if sig in primary_set:
                self.stats['primary_explored_roots'] += 1
            self.root_limit = min(self.max_steps, self.steps + (per_root if sig in primary_set else 200))
            initial = {}
            if sig in entries:
                name = sig.split('->')[-1].split('(')[0]
                # onCreate savedInstanceState is not an externally supplied Bundle.
                if name in {'onNewIntent', 'onReceive', 'onStartCommand', 'onBind', 'onHandleIntent',
                            'query', 'insert', 'update', 'delete', 'openFile', 'call'}:
                    types = re.findall(r'\[*L[^;]+;|\[*[ZBCSIFJD]', sig.split('(', 1)[1].split(')', 1)[0])
                    slots = iter(program.methods[sig].parameter_registers[1:])
                    for typ in types:
                        reg = next(slots, None)
                        if typ in ('J', 'D'):
                            next(slots, None)
                        if reg is not None and typ in ('Landroid/content/Intent;', 'Landroid/net/Uri;', 'Ljava/lang/String;'):
                            initial[reg] = Trace('external callback argument', ((sig, 0,
                                                 'possible external entry argument (configuration unresolved)'
                                                 if sig in self.uncertain_entries else 'external entry argument'),),
                                                 sig not in self.uncertain_entries, sig in self.uncertain_entries)
            self._walk(sig, initial, {}, (), sig in entries)
            if self.steps >= self.root_limit and self.root_limit < self.max_steps:
                self.diagnostics.add('Per-root flow budget reached: ' + sig)
            if self.steps >= self.max_steps:
                self.diagnostics.add('Flow exploration step budget exhausted; analysis is incomplete')
                break
        self.stats['steps'] = self.steps
        self.stats['boundaries'] = list(self.boundaries.values())
        self.diagnostics.update(self.resolver.diagnostics)
        return list(self.findings.values()), sorted(self.diagnostics)

    def _walk(self, sig, initial, fields, stack, external, memory=None):
        memory = memory or Memory()
        input_memory = memory
        if sig in stack or len(stack) >= self.max_depth:
            self.diagnostics.add('Recursion/call-depth boundary reached: ' + sig)
            return [(None, fields, memory)]
        method = self.program.methods[sig]
        if not method.instructions:
            return [(None, fields, memory)]
        code = {i.offset: i for i in method.instructions}
        queue = deque([(method.instructions[0].offset, dict(initial), dict(fields), None, {}, memory)])
        outcomes = []
        while queue and self.steps < self.root_limit:
            self.cancel.check()
            offset, regs, heap, pending, visits, previous = queue.popleft()
            memory = previous.copy()
            memory.result_ref = memory.result_constant = None
            if offset not in code:
                self.diagnostics.add('Unresolved CFG successor: ' + sig)
                continue
            if visits.get(offset, 0) >= 2:
                self.diagnostics.add('Loop path bound reached: ' + sig)
                continue
            visits = {**visits, offset: visits.get(offset, 0) + 1}
            self.steps += 1
            ins = code[offset]
            op, rr = ins.opcode, ins.registers
            old = dict(regs)
            # Strong register updates avoid stale taint after a constant/new value.
            for register in ins.defs:
                regs.pop(register, None)
                memory.kill(register)
            next_pending = None
            call_outcomes = None
            if op.startswith('move-result') and rr:
                regs.pop(rr[0], None)
                memory.kill(rr[0])
                if pending:
                    regs[rr[0]] = pending.step(sig, offset, 'return value')
                if previous.result_ref is not None:
                    memory.refs[rr[0]] = previous.result_ref
                if previous.result_constant is not None:
                    memory.constants[rr[0]] = previous.result_constant
            elif op.startswith('move') and op != 'move-exception' and len(rr) >= 2:
                regs.pop(rr[0], None)
                memory.kill(rr[0])
                if rr[1] in old:
                    regs[rr[0]] = old[rr[1]].step(sig, offset, 'register move')
                if rr[1] in previous.refs:
                    memory.refs[rr[0]] = previous.refs[rr[1]]
                if rr[1] in previous.constants:
                    memory.constants[rr[0]] = previous.constants[rr[1]]
            elif op.startswith(('const', 'new-instance', 'new-array')) and rr:
                regs.pop(rr[0], None)
                memory.kill(rr[0])
                if op.startswith('const'):
                    memory.constants[rr[0]] = ClassConstant(ins.literal) if op == 'const-class' else ins.literal
                elif op == 'new-array':
                    from analyzer.core.arrayflow import allocate
                    allocate(ins, memory, previous, self.diagnostics.add)
                elif op == 'new-instance' and tracked_type(self.program, ins.literal, self.resolver):
                    from analyzer.core.listflow import MAX_LIST_OBJECTS
                    from analyzer.core.objectflow import ARRAYLIST, HASHMAP
                    from analyzer.core.mapflow import MAX_MAP_OBJECTS
                    if ins.literal == ARRAYLIST and sum(obj.type == ARRAYLIST for obj in memory.objects.values()) >= MAX_LIST_OBJECTS:
                        self.diagnostics.add('ArrayList allocation budget exceeded: ' + sig)
                    elif ins.literal == HASHMAP and sum(obj.type == HASHMAP for obj in memory.objects.values()) >= MAX_MAP_OBJECTS:
                        self.diagnostics.add('HashMap allocation budget exceeded: ' + sig)
                    else:
                        memory.sequence += 1
                        identity = ('allocation', memory.sequence)
                        memory.refs[rr[0]] = identity
                        memory.objects[identity] = ObjectValue(ins.literal)
            elif op in ('add-int', 'sub-int', 'add-int/2addr', 'sub-int/2addr', 'mul-int', 'mul-int/2addr'):
                from analyzer.core.intflow import register_arithmetic
                register_arithmetic(ins, old, regs, memory, previous, sig, self.diagnostics.add)
            elif op in ('add-int/lit8', 'add-int/lit16', 'mul-int/lit8', 'mul-int/lit16'):
                from analyzer.core.intflow import literal_arithmetic
                literal_arithmetic(ins, old, regs, memory, previous, sig, self.diagnostics.add)
            elif op == 'array-length':
                from analyzer.core.arrayflow import length
                length(ins, regs, memory, previous, sig, self.diagnostics.add)
            elif op in ('aput-object', 'aget-object'):
                from analyzer.core.arrayflow import access
                if op == 'aget-object' and rr:
                    regs.pop(rr[0], None)
                    memory.kill(rr[0])
                access(ins, old, regs, memory, previous, sig, self.diagnostics.add)
            elif op in ('filled-new-array', 'filled-new-array/range'):
                from analyzer.core.arrayflow import allocate_filled
                allocate_filled(ins, old, memory, previous, sig, self.diagnostics.add)
            elif op.startswith(('aget', 'aput', 'filled-new-array', 'fill-array-data')):
                self.diagnostics.add('Unsupported array opcode: ' + op)
            elif op.startswith(('iput', 'sput')) and rr:
                obj = previous.object(rr[1]) if op.startswith('iput') and len(rr) > 1 else None
                value = old.get(rr[0])
                if obj:
                    values = dict(obj.fields)
                    references = dict(obj.field_refs)
                    references.pop(ins.target, None)
                    if op == 'iput-object' and rr[0] in previous.refs:
                        references[ins.target] = previous.refs[rr[0]]
                    values[ins.target] = value.step(sig, offset, 'object field write ' + ins.target) if value else None
                    memory.update(rr[1], fields=values, field_refs=references)
                else:
                    heap.pop(ins.target, None)
                    if value:
                        heap[ins.target] = value.step(sig, offset, 'field write ' + ins.target, True)
            elif op.startswith(('iget', 'sget')) and rr:
                regs.pop(rr[0], None)
                memory.kill(rr[0])
                obj = previous.object(rr[1]) if op.startswith('iget') and len(rr) > 1 else None
                if obj:
                    if op == 'iget-object' and ins.target in obj.field_refs:
                        memory.refs[rr[0]] = obj.field_refs[ins.target]
                    value = obj.fields.get(ins.target)
                    if value:
                        regs[rr[0]] = value.step(sig, offset, 'object field read ' + ins.target)
                elif ins.target in heap:
                    regs[rr[0]] = heap[ins.target].step(sig, offset, 'field read ' + ins.target, True)
            elif op == 'check-cast' and rr:
                if rr[0] in old:
                    regs[rr[0]] = old[rr[0]]
                if rr[0] in previous.refs:
                    memory.refs[rr[0]] = previous.refs[rr[0]]
            elif op.startswith('return'):
                value = old.get(rr[0]) if rr and op != 'return-void' else None
                if value:
                    value = value.step(sig, offset, 'method return')
                if rr and op != 'return-void':
                    memory.result_ref = previous.refs.get(rr[0])
                    memory.result_constant = previous.constants.get(rr[0])
                outcomes.append((value, heap, memory))
                if len(outcomes) >= 32:
                    self.diagnostics.add('Return-path budget reached: ' + sig)
                    break
                continue
            elif op.startswith('invoke'):
                ins = replace(ins, target=self.resolver.target(ins.target))
                values = [old.get(r) for r in rr]
                local_intent, intent_value = intent_call(ins.target, rr, old, regs, memory, previous,
                                                        sig, offset, self.diagnostics.add)
                from analyzer.core.arrayflow import copy_call, clone_call, copy_of_call, fill_call
                from analyzer.core.listflow import list_call
                local_list, list_value = list_call(ins, old, memory, previous, sig, self.diagnostics.add)
                from analyzer.core.mapflow import map_call
                local_map, map_value = map_call(ins, old, memory, previous, sig, self.diagnostics.add)
                local_array = (fill_call(ins, old, memory, previous, sig, self.diagnostics.add)
                               or copy_call(ins, memory, previous, sig, self.diagnostics.add)
                               or clone_call(ins, memory, previous, sig, self.diagnostics.add)
                               or copy_of_call(ins, memory, previous, sig, self.diagnostics.add))
                modeled_sink = False
                for rule in self.rules['sinks']:
                    if any(ins.target.startswith(s) for s in rule['signatures']):
                        modeled_sink = True
                        for n in rule['arguments']:
                            if n < len(values) and values[n]:
                                conditions = rule.get('required_conditions', [])
                                status = evaluate_conditions(conditions, rr, previous.constants, values[n])
                                if conditions:
                                    self.stats['required_condition_observations'][status] += 1
                                if status != 'NOT_MET':
                                    self._finding(rule, sig, ins, values[n], status if conditions else None)
                if local_map:
                    next_pending = map_value
                elif local_list:
                    next_pending = list_value
                elif local_array:
                    pass  # Path-local array effects / optional result_ref were modeled above.
                elif local_intent:
                    next_pending = intent_value
                elif ins.target in ASYNC_CALLS | ICC_CALLS:
                    self._boundary(sig, ins, previous, heap, stack, external)
                elif (ins.target == 'Landroid/app/Activity;->getIntent()Landroid/content/Intent;'
                      and rr and previous.object(rr[0]) and previous.object(rr[0]).intent_ref is not None):
                    memory.result_ref = previous.object(rr[0]).intent_ref
                elif any(ins.target.startswith(s) for s in self.rules['sources']):
                    # Source APIs are modeled as untrusted reads, but external provenance
                    # requires a framework-origin receiver tracked from an entry point.
                    receiver = values[0] if values else None
                    trusted_origin = bool(receiver and receiver.external)
                    prior = receiver.steps if receiver else ()
                    next_pending = Trace(ins.target, prior + ((sig, offset, 'source ' + ins.target),),
                                         trusted_origin, bool(receiver and receiver.uncertain))
                elif ins.target == 'Landroid/app/Activity;->getIntent()Landroid/content/Intent;' and external:
                    # Only the lifecycle's original this register may establish provenance.
                    if (rr and method.parameter_registers and rr[0] == method.parameter_registers[0] and not stack
                            and not any(rr[0] in prior.defs for prior in method.instructions if prior.offset < offset)):
                        next_pending = Trace(ins.target, ((sig, offset, 'possible entry / getIntent'
                                             if sig in self.uncertain_entries else 'external entry / getIntent'),),
                                             sig not in self.uncertain_entries, sig in self.uncertain_entries)
                elif ins.target in self.transfers:
                    transfer = self.transfers[ins.target]
                    candidates = [values[n] for n in transfer['arguments'] if n < len(values) and values[n]]
                    value = next((v for v in candidates if v.external), next(iter(candidates), None))
                    if value:
                        next_pending = value.step(sig, offset, 'argument-scoped library transfer ' + ins.target,
                                                  transfer.get('uncertain', False))
                elif ins.target in self.program.methods:
                    callee = self.program.methods[ins.target]
                    callee_memory = previous.arguments(rr, callee.parameter_registers)
                    arguments = {}
                    virtual = not op.startswith(('invoke-static', 'invoke-direct'))
                    if virtual:
                        for identity, obj in list(callee_memory.objects.items()):
                            if obj.map_items is not None:
                                callee_memory.objects[identity] = replace(obj, map_items={
                                    key: value.step(sig, offset, 'map through unresolved dispatch', True) if value else None
                                    for key, value in obj.map_items.items()})
                            if obj.array_length is not None:
                                callee_memory.objects[identity] = replace(obj, array_elements={
                                    key: value.step(sig, offset, 'array through unresolved dispatch', True) if value else None
                                    for key, value in obj.array_elements.items()})
                            if obj.list_items is not None:
                                callee_memory.objects[identity] = replace(obj, list_items=tuple(
                                    value.step(sig, offset, 'list through unresolved dispatch', True) if value else None
                                    for value in obj.list_items))
                    for register, value in zip(callee.parameter_registers, values):
                        if value:
                            arguments[register] = value.step(sig, offset, 'argument → ' + ins.target, virtual)
                    if not arguments and not heap and not callee_memory.refs and ins.target not in self.source_reachable:
                        self.stats['skipped_untainted_calls'] += 1
                        call_outcomes = [(None, heap, memory)]
                    else:
                        call_outcomes = [(value, outgoing, memory.returned(returned)) for value, outgoing, returned in
                            self._walk(ins.target, arguments, heap, stack + (sig,), external, callee_memory)]
                elif any(values) and not modeled_sink:
                    self.diagnostics.add('Unmodeled external call on tainted value: ' + ins.target)
                if (not local_intent and not local_array and not local_list and not local_map and ins.target not in self.program.methods
                        and ins.target not in ASYNC_CALLS | ICC_CALLS
                        and ins.target != 'Landroid/app/Activity;->getIntent()Landroid/content/Intent;'):
                    for register in rr:
                        obj = previous.object(register)
                        if obj:
                            pending_refs, seen_refs = [previous.refs[register]], set()
                            while pending_refs:
                                self.cancel.check()
                                identity = pending_refs.pop()
                                if identity in seen_refs:
                                    continue
                                seen_refs.add(identity)
                                nested = memory.objects.get(identity)
                                if nested is not None:
                                    pending_refs.extend(nested.field_refs.values())
                                    if nested.intent_ref is not None:
                                        pending_refs.append(nested.intent_ref)
                                    if nested.iterator_ref is not None:
                                        pending_refs.append(nested.iterator_ref)
                                    memory.objects[identity] = ObjectValue(nested.type)
                            self.diagnostics.add('Unmodeled external call on tracked object: ' + ins.target)
            # Branch predicates are not solved. Every real CFG successor is explored.
            branches = call_outcomes if call_outcomes is not None else [(next_pending, heap, memory)]
            for value, outgoing_heap, outgoing_memory in branches:
                for successor in ins.successors:
                    queue.append((successor, dict(regs), dict(outgoing_heap), value, visits, outgoing_memory))
            if len(queue) > 512:
                self.diagnostics.add('CFG path queue budget reached: ' + sig)
                queue = deque(list(queue)[:512])
        return outcomes or [(None, fields, input_memory)]

    def _boundary(self, sig, ins, memory, heap, stack, external):
        kind = 'ASYNC' if ins.target in ASYNC_CALLS else 'ICC'
        rr = ins.registers
        obj = memory.object(rr[1]) if len(rr) > 1 else None
        target = ''
        entry_memory = Memory(objects=dict(memory.objects), sequence=memory.sequence)
        if kind == 'ASYNC' and obj:
            target = self.resolver.target(obj.type + '->run()V')
            if target in self.program.methods and self.program.methods[target].parameter_registers:
                entry_memory.refs[self.program.methods[target].parameter_registers[0]] = memory.refs[rr[1]]
        elif (kind == 'ICC' and obj and obj.target and ins.opcode in ('invoke-virtual', 'invoke-virtual/range')
              and len(rr) == (3 if ('Landroid/os/Bundle;' in ins.target or
                                   'sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)' in ins.target) else 2)):
            component_kind = ICC_COMPONENT_KIND.get(ins.target, 'activity')
            allowed = ('activity', 'activity-alias') if component_kind == 'activity' else (component_kind,)
            component = next((c for c in self.manifest.get('components', [])
                if c.get('enabled') is not False and c.get('kind') in allowed
                and (obj.target_package is None or obj.target_package == self.manifest.get('package'))
                and 'L' + c.get('name', '').replace('.', '/') + ';' == obj.target), None)
            if component:
                descriptor = 'L' + component.get('target', component['name']).replace('.', '/') + ';'
                callback, minimum, intent_slot = {
                    'activity': ('onCreate(Landroid/os/Bundle;)V', 1, None),
                    'service': ('onStartCommand(Landroid/content/Intent;II)I', 4, 1),
                    'receiver': ('onReceive(Landroid/content/Context;Landroid/content/Intent;)V', 3, 2),
                }[component_kind]
                target = self.resolver.target(descriptor + '->' + callback)
                params = self.program.methods[target].parameter_registers if target in self.program.methods else []
                if len(params) >= minimum:
                    identity = (component_kind, sig, ins.offset, stack)
                    entry_memory.objects[identity] = ObjectValue(descriptor, intent_ref=memory.refs[rr[1]])
                    entry_memory.refs[params[0]] = identity
                    if intent_slot is not None:
                        entry_memory.refs[params[intent_slot]] = memory.refs[rr[1]]
        connected = target in self.program.methods and bool(entry_memory.refs)
        key = (kind, sig, ins.offset, target)
        if len(self.boundaries) < 1000 or key in self.boundaries:
            self.boundaries[key] = dict(kind=kind, method=sig, offset=ins.offset,
                target=target, status='MODELED_POTENTIAL' if connected else 'UNRESOLVED',
                component_kind=ICC_COMPONENT_KIND.get(ins.target, ''), runtime_delivery='UNKNOWN')
        else:
            self.diagnostics.add('Boundary inventory budget reached')
        if not connected:
            self.diagnostics.add('Unresolved ' + kind + ' boundary: ' + sig + ' @ ' + str(ins.offset))
            return
        label = kind + ' boundary (scheduling/lifecycle unproven) → ' + target
        def mark(trace):
            return trace.step(sig, ins.offset, label, True) if trace else None
        # Snapshot only: callback effects/return values never become synchronous
        # caller effects. No task ordering, launch success or accepting branch is proven.
        for identity, value in list(entry_memory.objects.items()):
            entry_memory.objects[identity] = replace(value,
                fields={k: mark(v) for k, v in value.fields.items()},
                extras={k: mark(v) for k, v in value.extras.items()}, data=mark(value.data),
                array_elements={k: mark(v) for k, v in value.array_elements.items()},
                map_items={k: mark(v) for k, v in value.map_items.items()} if value.map_items is not None else None,
                list_items=tuple(mark(v) for v in value.list_items) if value.list_items is not None else None)
        self.diagnostics.add(kind + ' boundary explored with scheduling/lifecycle uncertainty: ' + target)
        self._walk(target, {}, {k: mark(v) for k, v in heap.items()}, stack + (sig,), False, entry_memory)

    def _finding(self, rule, method, ins, trace, condition_status=None):
        trace = trace.step(method, ins.offset, 'sink ' + ins.target)
        methods = list(dict.fromkeys(s[0] for s in trace.steps))
        level = 'L5' if trace.external else 'L4' if len(methods) > 1 else 'L3'
        path = [dict(method=m, offset=o, label=label) for m, o, label in trace.steps]
        finding = Finding(rule['id'], rule['title'],
            'A modeled DEX register path connects untrusted input to a sensitive argument. '
            'Branch feasibility and validation require analyst verification.', rule['category'],
            type='VULNERABILITY', severity=rule['severity'],
            confidence='MEDIUM' if trace.uncertain or not trace.external else 'HIGH',
            verification='POTENTIAL' if trace.uncertain or not trace.external else 'LIKELY',
            analysis_level=level, location=Location(self.program.methods[method].class_name, method, ins.offset),
            source=trace.source, sink=ins.target, data_flow=path,
            attack_path=path if trace.external else [], related_methods=methods,
            evidence=['Original DEX offsets and modeled register propagation',
                      'Branch conditions unresolved; no automatic exploitability confirmation',
                      'Entry configuration, field aliasing, virtual dispatch or scheduling/lifecycle uncertainty' if trace.uncertain
                      else 'No modeled alias/dispatch/boundary uncertainty'],
            bytecode='\n'.join(f'{i.offset:04x}  {i.text or i.opcode}' for i in self.program.methods[method].instructions),
            validation={'scheme_allowlist': 'UNKNOWN', 'host_allowlist': 'UNKNOWN', 'null_check': 'UNKNOWN'},
            recommendation='Validate external input at the trust boundary; constrain the sink argument and verify accepting branches.',
            standards={'cwe': rule.get('cwe', [])})
        if condition_status:
            finding.validation['required_conditions'] = condition_status
            finding.evidence.append('Declarative required conditions: ' + condition_status + '; not a runtime guarantee')
            if condition_status == 'UNKNOWN':
                finding.type = 'REVIEW'
                finding.verification = 'MANUAL_REVIEW'
                finding.confidence = 'LOW'
                finding.attack_path = []
        existing = self.findings.get(finding.id)
        def rank(item):
            return (item.validation.get('required_conditions') != 'UNKNOWN', item.analysis_level)
        if existing is None or rank(finding) > rank(existing):
            self.findings[finding.id] = finding
