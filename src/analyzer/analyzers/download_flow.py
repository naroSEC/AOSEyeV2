"""Downloaded-record URI provenance, not proof that remote bytes execute."""
from pathlib import Path
from analyzer.core.dataflow import FlowEngine
from analyzer.core.rules.registry import RuleRegistry


def download_flows(program, cancel, max_steps=100000, max_depth=8):
    rules = RuleRegistry(Path(__file__).parents[1] / 'core/rules/download.yaml')
    engine = FlowEngine(rules, max_steps, max_depth)
    findings, diagnostics = engine.analyze(program, set(), cancel, include_boundary_roots=False)
    for finding in findings:
        finding.type = 'REVIEW'
        finding.verification = 'MANUAL_REVIEW'
        finding.confidence = 'MEDIUM'
        finding.attack_path = []
        finding.validation.update(download_origin='UNKNOWN', downloaded_bytes_integrity='UNKNOWN',
                                  filesystem_path_validity='UNKNOWN', class_execution='UNKNOWN')
        finding.description = (
            'A modeled path connects DownloadManager record-URI lookup to a loader code-path argument. '
            'The URI may be null or content-based; getPath/toString do not establish a usable filesystem path. '
            'Download success, remote origin, integrity checks, loader success and execution are unverified.')
        finding.evidence = ['Download-record URI source and argument-scoped DEX propagation',
                            'No download, file access, loader construction or class execution was performed']
        finding.recommendation = (
            'Review download ownership, URI resolution, integrity/signature verification and loader use. '
            'A missing modeled check is not proof that the application lacks validation.')
    return findings, ['Download flow: ' + d for d in diagnostics], dict(
        engine.stats, rules_sha256=rules.fingerprint, step_limit=max_steps,
        scope='DownloadManager record URI to DexClassLoader/PathClassLoader code-path argument only')
