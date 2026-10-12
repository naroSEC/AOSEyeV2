"""Credential-return flows kept separate from attacker-controlled input flows."""
from pathlib import Path
from analyzer.core.dataflow import FlowEngine
from analyzer.core.rules.registry import RuleRegistry


def sensitive_flows(program, cancel, max_steps=100000, max_depth=8):
    rules = RuleRegistry(Path(__file__).parents[1] / 'core/rules/sensitive.yaml')
    engine = FlowEngine(rules, max_steps, max_depth)
    # No external entry seeds: an Intent extra alone cannot become a secret.
    findings, diagnostics = engine.analyze(program, set(), cancel, include_boundary_roots=False)
    for finding in findings:
        finding.type = 'REVIEW'
        finding.verification = 'MANUAL_REVIEW'
        finding.confidence = 'MEDIUM'
        finding.attack_path = []
        finding.validation.update({'credential_validity': 'UNKNOWN', 'destination_protection': 'UNKNOWN',
                                   'persistence_or_exposure': 'UNKNOWN'})
        finding.description = (
            'A modeled DEX path connects a credential-return API to this argument. '
            'The return may be null; runtime reachability, credential validity and destination protection are unknown. '
            'Editor/bind calls do not prove commit or execution. A stream may be memory-backed or protected; '
            'cache/external-storage location and third-party access are not established.')
        finding.recommendation = (
            'Inspect the source-to-argument evidence and destination protection. Avoid logging or copying live credentials; '
            'verify whether editor/bind operations are executed and whether persisted values require encryption.')
        finding.evidence = ['Credential-return source and argument-scoped DEX propagation',
                            'Static candidate only; no live credentials were fetched or validated',
                            'Branch predicates and runtime protection remain unverified']
    coverage = dict(engine.stats, rules_sha256=rules.fingerprint, step_limit=max_steps,
                    scope='AccountManager credential returns only; separate bounded pass; no external-input seeds')
    return findings, ['Sensitive flow: ' + d for d in diagnostics], coverage
