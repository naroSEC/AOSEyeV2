"""Review presentation derived from saved DEX, not trusted report offsets."""
import json
from analyzer.analyzers.url_validation import url_guard_review, EQUALS
from analyzer.analyzers.exception_flow import exception_edges


def review_view(program, finding, cancel, limit=300):
    cancel.check()
    review = url_guard_review(program, finding.location.method, finding.location.offset, cancel)
    links, seen, methods, warnings = [], set(), set(), []
    truncated = False
    def add(label, signature, offset):
        nonlocal truncated
        cancel.check()
        method = program.methods.get(signature)
        if not method or type(offset) is not int or not any(i.offset == offset for i in method.instructions):
            warnings.append('Unindexed location omitted')
            return
        key = label, signature, offset
        if key in seen:
            return
        seen.add(key)
        if len(links) >= limit:
            truncated = True
            return
        links.append(dict(label=label, method=signature, offset=offset, unit=method.unit))

    if finding.location.method in program.methods:
        methods.add(finding.location.method)
    for evidence in review['evidence']:
        signature = evidence['method']
        method = program.methods.get(signature)
        if not method:
            continue
        methods.add(signature)
        code = {i.offset: i for i in method.instructions}
        equality = code.get(evidence['equality_offset'])
        branch = code.get(evidence['branch_offset'])
        if not equality or equality.target != EQUALS or not branch:
            warnings.append('Comparison evidence did not match indexed DEX')
            continue
        component = evidence['component']
        add(component + ' · exact comparison', signature, equality.offset)
        if evidence['proof_kind'] == 'TRUE_RETURN_IMPLIES_EQUALITY' and branch.opcode == 'return':
            add(component + ' · boolean return', signature, branch.offset)
        elif branch.opcode in ('if-eqz', 'if-nez'):
            successors = branch.normal_successors if branch.normal_successors is not None else branch.successors
            if evidence['accepting_successor'] in successors:
                add(component + ' · guard branch', signature, branch.offset)
                add(component + ' · accepting successor', signature, evidence['accepting_successor'])
    pending = [(finding.location.method, review['helper_calls'])]
    while pending:
        caller, calls = pending.pop()
        cancel.check()
        method = program.methods.get(caller)
        code = {i.offset: i for i in method.instructions} if method else {}
        for call in calls:
            ins = code.get(call['call_offset'])
            if not ins or ins.target != call['method'] or not ins.opcode.startswith('invoke-static'):
                warnings.append('Helper call did not match indexed DEX')
                continue
            add('Helper call · ' + call['status'], caller, ins.offset)
            methods.add(call['method'])
            pending.append((call['method'], call['nested']))
    for signature in sorted(methods):
        cancel.check()
        method = program.methods[signature]
        if method.exception_status != 'PRESENT':
            continue
        try:
            exception_edges(method, {i.offset: i for i in method.instructions})
        except ValueError as exc:
            warnings.append('Handler links omitted: ' + str(exc))
            continue
        for region in method.exception_regions:
            add('Try start · declared range', signature, region['start'])
            for handler in region['handlers']:
                add('Handler · declared, execution unproven', signature, handler['address'])
    if truncated:
        warnings.append(f'Navigation truncated at {limit} links')
    summary = (f"URL guard: {review['status']}\n"
               f"Scheme: {review['scheme_allowlist']} · Host: {review['host_allowlist']}\n"
               'Recomputed from saved DEX · not a safety verdict; findings unchanged.\n'
               f'{len(links)} checked locations' + (' · truncated' if truncated else '') +
               ('\n' + review['reason'] if review.get('reason') else ''))
    content = json.dumps(dict(current_url_validation=review, navigation_warnings=warnings,
                              saved_candidate_review=finding.review), ensure_ascii=True, indent=2)
    return summary, content, links
