"""Bounded declared-call reachability and CFG guard context, not a safety solver."""
from collections import deque
from analyzer.core.graph import DeclarationResolver
from analyzer.analyzers.manifest import entry_catalog


class CandidateReviewer:
    def __init__(self, program, manifest, boundaries=(), cancel=None):
        self.program, self.cancel = program, cancel
        self.reverse = {}
        self.resolver = DeclarationResolver(program)
        catalog = entry_catalog(manifest, program.methods, program.class_hierarchy, program.method_index)
        self.entries = set(catalog['confirmed'])
        self.uncertain_entries = set(catalog['uncertain'])
        self.entry_configurations = {}
        self.entry_configurations_truncated = set()
        for record in catalog['records']:
            if record['status'] not in ('UNCERTAIN', 'CONFIRMED_CONFIGURATION'):
                continue
            rows = self.entry_configurations.setdefault(record['method'], [])
            if len(rows) < 20:
                rows.append(record)
            else:
                self.entry_configurations_truncated.add(record['method'])
        for method in program.methods.values():
            if cancel:
                cancel.check()
            for ins in method.instructions:
                if ins.opcode.startswith('invoke'):
                    target = self.resolver.target(ins.target)
                    if target in program.methods:
                        self.reverse.setdefault(target, []).append(dict(
                            caller=method.signature, callee=target, offset=ins.offset, kind='DECLARED_CALL'))
        for edge in boundaries:
            if edge['status'] == 'MODELED_POTENTIAL' and edge['target'] in program.methods:
                self.reverse.setdefault(edge['target'], []).append(dict(
                    caller=edge['method'], callee=edge['target'], offset=edge['offset'],
                    kind=edge['kind'] + '_POTENTIAL'))

    def reachability(self, target, max_nodes=10000, max_depth=32):
        if target not in self.program.methods:
            return dict(status='UNAVAILABLE', paths=[], truncated=False)
        pending = deque([(target, [])])
        enqueued = {target}
        seen, paths, truncated = set(), [], False
        while pending:
            if self.cancel:
                self.cancel.check()
            if len(seen) >= max_nodes:
                truncated = True
                break
            method, path = pending.popleft()
            if method in seen:
                continue
            seen.add(method)
            if method in self.entries | self.uncertain_entries:
                paths.append(dict(entry=method, edges=path, configuration_uncertain=method in self.uncertain_entries,
                                  entry_configurations=self.entry_configurations.get(method, []),
                                  entry_configurations_truncated=method in self.entry_configurations_truncated))
                # A witness suffices; do not claim to enumerate every path.
                break
            incoming = self.reverse.get(method, [])
            if len(path) >= max_depth:
                truncated |= bool(incoming)
                continue
            for edge in incoming:
                if edge['caller'] in enqueued:
                    continue
                if len(enqueued) >= max_nodes:
                    truncated = True
                    continue
                enqueued.add(edge['caller'])
                pending.append((edge['caller'], [edge] + path))
        return dict(status=('POSSIBLE_ENTRY_PATH_FOUND' if paths[0]['configuration_uncertain'] else 'DECLARED_PATH_FOUND')
                    if paths else 'INCOMPLETE' if truncated
                    else 'NO_MODELED_PATH_FOUND', paths=paths, truncated=truncated,
                    visited_methods=len(seen), direct_callers=self.reverse.get(target, [])[:100],
                    direct_callers_truncated=len(self.reverse.get(target, [])) > 100,
                    scope='Declared DEX calls and explored potential boundaries; not input propagation, '
                          'runtime reachability, reflection/native coverage or proof of dead code.')

    def guard_context(self, signature, observation, max_nodes=2000, max_branches=128):
        method = self.program.methods.get(signature)
        if not method or not method.instructions:
            return dict(method=signature, observation=observation, status='UNAVAILABLE', branches=[])
        code = {i.offset: i for i in method.instructions}
        if len(code) > max_nodes or observation not in code:
            return dict(method=signature, observation=observation, status='LIMITED', branches=[])
        predecessors = {}
        unresolved = False
        for ins in code.values():
            for successor in ins.successors:
                if successor not in code:
                    unresolved = True
                else:
                    predecessors.setdefault(successor, []).append(ins.offset)
        def reachable(start, blocked=None, goal=observation):
            queue, seen = [start], set()
            while queue:
                current = queue.pop()
                if current == blocked or current in seen or current not in code:
                    continue
                if current == goal:
                    return True
                seen.add(current)
                queue.extend(code[current].successors)
            return False
        entry = method.instructions[0].offset
        branches = []
        truncated = False
        for ins in method.instructions:
            if self.cancel:
                self.cancel.check()
            if (not ins.opcode.startswith('if-') or not reachable(ins.offset)
                    or not reachable(entry, goal=ins.offset)):
                continue
            if len(branches) >= max_branches:
                truncated = True
                break
            hits = [s for s in ins.successors if reachable(s)]
            branch = dict(offset=ins.offset, opcode=ins.opcode,
                          dominates_observation=reachable(entry) and not reachable(entry, ins.offset),
                          successors=list(ins.successors), reaching_successors=hits,
                          classification='BOTH_SUCCESSORS_REACH' if len(hits) == 2
                          else 'ONE_SUCCESSOR_REACHES' if len(hits) == 1 else 'OTHER')
            pred = predecessors.get(ins.offset, [])
            # Only annotate an unambiguous immediate invoke-result predicate.
            if len(pred) == 1:
                move = code[pred[0]]
                before = predecessors.get(move.offset, [])
                if (move.opcode.startswith('move-result') and move.registers == ins.registers
                        and len(before) == 1 and code[before[0]].opcode.startswith('invoke')):
                    call = code[before[0]]
                    branch['predicate_call'] = dict(offset=call.offset, declared_target=call.target)
            branches.append(branch)
        return dict(method=signature, observation=observation,
                    status='LIMITED' if truncated or unresolved else 'STRUCTURAL_ONLY', branches=branches,
                    caveat='CFG dominance/reachability does not establish value identity, predicate meaning, '
                           'accepting branch, sanitizer correctness or runtime feasibility.')

    def annotate(self, finding):
        from analyzer.analyzers.url_validation import url_guard_review
        url_review = url_guard_review(self.program, finding.location.method, finding.location.offset, self.cancel)
        finding.review['url_validation'] = url_review
        for key in ('scheme_allowlist', 'host_allowlist'):
            finding.validation[key] = url_review[key]
        finding.review['declaration_diagnostics'] = sorted(self.resolver.diagnostics)
        finding.review['reachability'] = self.reachability(finding.location.method)
        observations = {(finding.location.method, finding.location.offset)}
        observations.update((step['method'], step['offset']) for step in finding.data_flow
                            if step['label'] == 'method return')
        finding.review['guard_context'] = [self.guard_context(m, o)
                                          for m, o in sorted((m, o) for m, o in observations if o is not None)]
        # Keep UNKNOWN: a found graph path or a dominating condition is not a proof.
        finding.validation['external_reachability'] = finding.review['reachability']['status']
