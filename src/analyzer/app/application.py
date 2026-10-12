from pathlib import Path
import logging
from analyzer.app.jobs import Cancellation
from analyzer.app.settings import Settings
from analyzer.backends.jeb.backend import JebBackend, file_hash
from analyzer.backends.base import BackendError
from analyzer.core.models import AnalysisResult
from analyzer.core.rules.registry import RuleRegistry
from analyzer.core.dataflow import FlowEngine
from analyzer.analyzers.apk import inspect_apk
from analyzer.analyzers.manifest import analyze_manifest, entry_catalog
from analyzer.analyzers.network_config import analyze_network_config
from analyzer.analyzers.security import api_reviews
from analyzer.analyzers.context import constant_context
from analyzer.analyzers.pending_intent import pending_intent_context
from analyzer.analyzers.crypto_material import crypto_material
from analyzer.analyzers.sensitive_flow import sensitive_flows
from analyzer.analyzers.download_flow import download_flows
from analyzer.analyzers.tls import tls_context
from analyzer.analyzers.tls_installation import tls_installation
from analyzer.analyzers.biometric import biometric_context
from analyzer.analyzers.trust_array import trust_array_context
from analyzer.analyzers.receiver_context import annotate_receiver_context
from analyzer.analyzers.sensitive_storage import annotate_sensitive_storage
from analyzer.analyzers.auth_verification import authentication_verification
from analyzer.analyzers.verification import CandidateReviewer

log = logging.getLogger(__name__)


class AnalysisApplication:
    def __init__(self, settings: Settings, backend=None):
        self.settings = settings
        self.backend = backend or JebBackend(settings)

    def analyze(self, path: Path, cancel: Cancellation, progress=lambda n, text: None) -> AnalysisResult:
        path = path.resolve(strict=True)
        result = AnalysisResult(str(path), file_hash(path, cancel))
        result.provenance = dict(backend=type(self.backend).__name__,
                                 version=getattr(self.backend, 'version', 'unknown'), engine='0.1.0',
                                 jvm_heap_limit_mib=self.settings.jvm_heap_mib,
                                 method_export_limit_mib=self.settings.max_export_mib,
                                 index_entries_per_kind=self.settings.max_index_entries,
                                 index_encoded_limit_mib=self.settings.max_index_mib)
        result.provenance['requested_index_order'] = self.settings.index_order
        cancel.check()
        progress(5, 'APK indexing')
        raw_manifest = b''
        if path.suffix.lower() == '.apk':
            result.files, raw_manifest, assets, diagnostics = inspect_apk(path, cancel)
            result.findings.extend(assets)
            result.diagnostics.extend(diagnostics)
        elif path.suffix.lower() != '.dex':
            raise ValueError('Select an APK or DEX file')
        progress(20, 'Manifest / assets analysis')
        progress(30, 'JEB DEX / CFG indexing')
        backend_ok = False
        try:
            result.program = self.backend.load(path, cancel)
            backend_ok = True
        except (BackendError, OSError, ValueError) as exc:
            log.warning('Backend analysis unavailable: %s', exc)
            result.diagnostics.append('JEB analysis unavailable: ' + str(exc))
        cancel.check()
        xml = result.program.manifest
        if not xml and raw_manifest.lstrip().startswith(b'<'):
            xml = raw_manifest.decode('utf-8-sig', errors='replace')
        if xml:
            try:
                result.manifest, findings = analyze_manifest(xml)
                result.diagnostics.extend(result.manifest.get('diagnostics', []))
                result.program.manifest = xml
                result.findings.extend(findings)
            except Exception as exc:
                result.diagnostics.append('Manifest parsing failed: ' + str(exc))
        elif raw_manifest:
            result.diagnostics.append('Binary AndroidManifest.xml requires a working JEB backend')
        if result.manifest and path.suffix.lower() == '.apk':
            resolver = getattr(self.backend, 'resolve_network_xml', None) if backend_ok else None
            ca_resolver = getattr(self.backend, 'resolve_ca_resource', None) if backend_ok else None
            policy, findings, diagnostics = analyze_network_config(path, result.manifest, cancel, resolver, ca_resolver)
            if policy is not None:
                result.manifest['network_security_config'] = policy
            result.findings.extend(findings)
            result.diagnostics.extend(diagnostics)
        progress(50, 'XREF / call graph indexing')
        if result.manifest and path.suffix.lower() == '.apk':
            from analyzer.analyzers.storage_config import analyze_storage_config
            inventory, findings, diagnostics = analyze_storage_config(path, result.manifest, cancel,
                getattr(self.backend, 'resolve_network_xml', None) if backend_ok else None,
                getattr(self.backend, 'resolve_named_storage_xml', None) if backend_ok else None)
            result.manifest['storage_config'] = inventory
            result.findings.extend(findings)
            result.diagnostics.extend(diagnostics)
        if backend_ok:
            from analyzer.core.call_coverage import call_coverage
            result.provenance['call_target_coverage'] = call_coverage(result.program, cancel)
        rules = RuleRegistry()
        result.provenance['rules_sha256'] = rules.fingerprint
        result.provenance['analysis_policy'] = 'bounded-object-boundaries-v1+candidate-review-v1+declaration-resolution-v2+url-guard-review-v2-exceptions+provider-operations-v1+bounded-reference-arrays-v11-length+bounded-arraylist-v16-array-addall+bounded-hashmap-v5-replace+bounded-int-v3-multiply'
        progress(60, 'Security API context review')
        reviews = api_reviews(result.program, rules)
        tls_callbacks = tls_context(result.program, cancel)
        contexts = constant_context(result.program) + tls_callbacks
        contexts.extend(tls_installation(result.program, tls_callbacks, cancel))
        contexts.extend(trust_array_context(result.program, tls_callbacks, cancel))
        contexts.extend(biometric_context(result.program, cancel))
        contexts.extend(authentication_verification(result.program, cancel))
        contexts.extend(crypto_material(result.program, cancel))
        contexts.extend(pending_intent_context(result.program, result.manifest, cancel))
        result.provenance['analysis_policy'] += '+pending-intent-v2-destination-copy'
        result.provenance['analysis_policy'] += '+crypto-material-v2-base64'
        result.provenance['analysis_policy'] += '+asset-config-v2-ipv6-assignments'
        result.provenance['analysis_policy'] += '+rule-conditions-v2-flags'
        result.provenance['analysis_policy'] += '+tls-setter-connections-v1'
        result.provenance['analysis_policy'] += '+biometric-callback-v1'
        result.provenance['analysis_policy'] += '+trust-array-v2-multiple'
        result.provenance['analysis_policy'] += '+certificate-assets-v1'
        result.provenance['analysis_policy'] += '+receiver-context-v2-bridge-registration'
        result.provenance['analysis_policy'] += '+explicit-service-receiver-icc-v1'
        result.provenance['analysis_policy'] += '+tracked-object-field-refs-v1'
        result.provenance['analysis_policy'] += '+signature-result-review-v1'
        result.provenance['analysis_policy'] += '+tls-callbacks-v2-interfaces+constant-context-v2+sqlite-assets-v1+crypto-parameters-v1'
        progress(70, 'CFG data flow / interprocedural analysis')
        engine = FlowEngine(rules, self.settings.max_flow_steps, self.settings.max_call_depth)
        catalog = entry_catalog(result.manifest, result.program.methods, result.program.class_hierarchy,
                                result.program.method_index)
        result.provenance['entrypoints'] = catalog
        result.diagnostics.extend(catalog['diagnostics'])
        flows, diagnostics = engine.analyze(result.program, set(catalog['confirmed']) | set(catalog['uncertain']), cancel,
                                          manifest=result.manifest, uncertain_entries=set(catalog['uncertain']))
        result.provenance['flow_coverage'] = engine.stats
        result.diagnostics.extend(result.program.diagnostics)
        result.diagnostics.extend(diagnostics)
        sensitive, sensitive_diagnostics, sensitive_coverage = sensitive_flows(
            result.program, cancel, max(0, self.settings.max_flow_steps - engine.steps), self.settings.max_call_depth)
        contexts.extend(sensitive)
        result.diagnostics.extend(sensitive_diagnostics)
        result.provenance['sensitive_flow_coverage'] = sensitive_coverage
        result.provenance['analysis_policy'] += '+sensitive-flows-v1'
        result.provenance['analysis_policy'] += '+sensitive-storage-context-v1'
        downloaded, download_diagnostics, download_coverage = download_flows(
            result.program, cancel,
            max(0, self.settings.max_flow_steps - engine.steps - sensitive_coverage['steps']),
            self.settings.max_call_depth)
        contexts.extend(downloaded)
        result.diagnostics.extend(download_diagnostics)
        result.provenance['download_flow_coverage'] = download_coverage
        result.provenance['analysis_policy'] += '+download-flows-v1'
        for method in result.program.methods.values():
            result.diagnostics.extend(method.signature + ': ' + d for d in method.diagnostics)
        progress(90, 'Attack path correlation')
        if flows:
            reviewer = CandidateReviewer(result.program, result.manifest, engine.stats.get('boundaries', []), cancel)
            for finding in flows:
                reviewer.annotate(finding)
        annotate_receiver_context(result.program, flows + contexts, cancel)
        annotate_sensitive_storage(result.program, sensitive, cancel)
        covered = {(f.location.method, f.location.offset) for f in flows + contexts}
        result.findings.extend(f for f in reviews if (f.location.method, f.location.offset) not in covered)
        result.findings.extend(flows)
        result.findings.extend(contexts)
        result.findings.extend(rules.run_plugins(result.program))
        result.findings = list({f.id: f for f in result.findings}.values())
        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        result.findings.sort(key=lambda f: (order[f.severity], f.title))
        result.complete = backend_ok and not result.diagnostics
        progress(100, 'Finished' if result.complete else 'Finished with coverage limitations')
        return result
