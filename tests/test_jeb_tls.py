"""Compile and statically inspect TLS positives/negatives; never execute APK."""
import os
import subprocess
from pathlib import Path
from zipfile import ZipFile
import pytest


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_real_tls_callbacks(tmp_path):
    from analyzer.app.application import AnalysisApplication
    from analyzer.app.settings import Settings
    from analyzer.app.jobs import Cancellation
    from analyzer.backends.jeb.backend import JebBackend
    from analyzer.app.project_manager import save_project, open_project
    aapt = Path(os.environ.get('AOSEYE_TEST_AAPT2', 'missing'))
    if not aapt.is_file():
        pytest.skip('Set AOSEYE_TEST_AAPT2')
    android = aapt.parents[2] / 'platforms/android-35/android.jar'
    settings = Settings(jvm_heap_mib=1024, cache_enabled=False)
    classes, dex = tmp_path / 'classes', tmp_path / 'dex'
    classes.mkdir()
    dex.mkdir()
    def run(args):
        result = subprocess.run(list(map(str, args)), capture_output=True, timeout=60)
        assert result.returncode == 0, result.stderr.decode('utf-8', errors='replace')
    run(['javac', '--release', '8', '-cp', android, '-d', classes,
         *sorted((Path(__file__).parent / 'fixtures/tls').glob('*.java'))])
    run([settings.java, '-cp', Path(settings.jeb_path) / 'bin/app/d8.jar', 'com.android.tools.r8.D8',
         '--min-api', '23', '--lib', android, '--output', dex, *sorted(classes.rglob('*.class'))])
    manifest = tmp_path / 'AndroidManifest.xml'
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.tls">'
                        '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><application>'
                        '<service android:name="test.ComponentDeliveryFixture$SinkService" android:exported="false"/>'
                        '<receiver android:name="test.ComponentDeliveryFixture$SinkReceiver" android:exported="false"/>'
                        '</application></manifest>', encoding='utf-8')
    apk = tmp_path / 'tls.apk'
    run([aapt, 'link', '-I', android, '--manifest', manifest, '-o', apk])
    with ZipFile(apk, 'a') as archive:
        archive.write(dex / 'classes.dex', 'classes.dex')
    with JebBackend(settings) as backend:
        result = AnalysisApplication(settings, backend).analyze(apk, Cancellation())
    findings = [f for f in result.findings if f.rule_id in ('AOS-TLS-001', 'AOS-TLS-002', 'AOS-TLS-003')]
    assert {f.rule_id for f in findings} == {'AOS-TLS-001', 'AOS-TLS-002', 'AOS-TLS-003'}
    assert len(findings) == 3
    assert all('Accept' in f.location.class_name or 'ProceedClient' in f.location.class_name for f in findings)
    assert all(f.verification == 'MANUAL_REVIEW' and not f.attack_path for f in findings)
    deliveries = [b for b in result.provenance['flow_coverage']['boundaries']
                  if b.get('component_kind') in ('service', 'receiver') and b['status'] == 'MODELED_POTENTIAL']
    assert {b['component_kind'] for b in deliveries} == {'service', 'receiver'}
    assert any('->named(' in b['method'] for b in deliveries)
    assert any('->otherPackage(' in b['method'] and b['status'] == 'UNRESOLVED'
               for b in result.provenance['flow_coverage']['boundaries'])
    for boundary in deliveries:
        assert any(f.location.method == boundary['target'] and
                   any('ICC boundary' in step['label'] for step in f.data_flow) for f in result.findings), (
                       boundary, [(f.location.method, [s['label'] for s in f.data_flow])
                                  for f in result.findings if 'ComponentDeliveryFixture' in f.location.method])
    assert any('ComponentDeliveryFixture$IntentTask;->run(' in f.location.method and
               any('ASYNC boundary' in step['label'] for step in f.data_flow) for f in result.findings)
    assert '+tls-callbacks-v2-interfaces' in result.provenance['analysis_policy']
    assert all(f.type == 'WEAKNESS' and f.severity == 'MEDIUM' for f in findings)
    assert result.program.class_interfaces['Ltest/TlsFixture$AcceptTrust;'] == ['Ljavax/net/ssl/X509TrustManager;']
    installations = [f for f in result.findings if f.rule_id in ('AOS-TLS-004', 'AOS-TLS-005')]
    assert len(installations) == 3
    assert all(f.analysis_level == 'L3' and len(f.data_flow) == 3 and not f.attack_path for f in installations)
    assert all('->installReject(' not in f.location.method for f in installations)
    trust_arrays = [f for f in result.findings if f.rule_id == 'AOS-TLS-006']
    assert len(trust_arrays) == 1 and '->installTrust(' in trust_arrays[0].location.method
    assert len(trust_arrays[0].data_flow) == 5 and not trust_arrays[0].attack_path
    multiple, = [f for f in result.findings if f.rule_id == 'AOS-TLS-007']
    assert '->installMultiple(' in multiple.location.method and multiple.type == 'REVIEW'
    assert multiple.validation['provider_selection'] == 'UNKNOWN'
    biometric = [f for f in result.findings if f.rule_id == 'AOS-AUTH-001']
    ignored, = [f for f in result.findings if f.rule_id == 'AOS-AUTH-002']
    assert 'SignatureResultFixture;->ignored(' in ignored.location.method and ignored.type == 'REVIEW'
    assert len(biometric) == 2
    assert all('$Forward;' in f.location.class_name and f.type == 'REVIEW' and
               f.verification == 'MANUAL_REVIEW' and not f.attack_path for f in biometric)
    sensitive = [f for f in result.findings if f.rule_id.startswith('AOS-SENSITIVE-')]
    assert len(sensitive) == 12
    assert {f.rule_id for f in sensitive} == {'AOS-SENSITIVE-%03d' % n for n in range(1, 7)}
    assert all('->negative(' not in f.location.method for f in sensitive)
    assert all(f.type == 'REVIEW' and f.verification == 'MANUAL_REVIEW' and not f.attack_path for f in sensitive)
    assert any(f.analysis_level == 'L4' and '->helper(' in f.location.method for f in sensitive)
    assert result.provenance['sensitive_flow_coverage']['primary_explored_roots'] > 0
    pref, = [f for f in sensitive if f.rule_id == 'AOS-SENSITIVE-003']
    assert pref.validation['editor_flush_call'] == 'MODELED'
    storage = [f for f in sensitive if 'SensitiveStorageFixture;' in f.location.method]
    assert len(storage) == 4
    for f in storage:
        linked = '->sql(' in f.location.method or '->file(' in f.location.method
        assert f.validation['storage_call_context'] == ('MODELED' if linked else 'UNKNOWN')
        if '->sql(' in f.location.method:
            assert f.review['sqlite_context']['transaction_commit'] == 'UNKNOWN'
        if '->file(' in f.location.method:
            assert f.validation['storage_requested_location'] == 'APP_INTERNAL_FILES'
            assert 'fixture-credential' not in str(f.review)
    web = [f for f in result.findings if f.rule_id == 'AOS-WEBVIEW-004' and
           'WebReceiverFixture;' in f.location.method]
    assert len(web) == 5
    for f in web:
        if '->other(' in f.location.method:
            assert f.validation['receiver_context'] == 'UNKNOWN'
        elif '->bridge(' in f.location.method:
            assert f.validation['webview_bridge_registration'] == 'MODELED'
            assert f.validation['webview_javascript'] == 'ENABLED'
            assert f.validation['webview_bridge_runtime_exposure'] == 'UNKNOWN'
        elif '->removedBridge(' in f.location.method:
            assert 'webview_bridge_registration' not in f.validation
        else:
            assert f.validation['webview_javascript'] == ('ENABLED' if '->enabled(' in f.location.method else 'DISABLED')
    # Exercise the declarative conditions against actual normalized DEX, not
    # decompiled text. No additional APK execution or JEB session is needed.
    from analyzer.core.rules.registry import RuleRegistry
    from analyzer.core.dataflow import FlowEngine
    import yaml
    config = RuleRegistry(Path(__file__).parents[1] / 'src/analyzer/core/rules/sensitive.yaml').config
    for rule in config['sinks']:
        rule['required_conditions'] = [{'kind': 'source_prefix', 'prefix':
            'Landroid/accounts/AccountManager;->peekAuthToken('}]
    rule_path = tmp_path / 'conditional.yaml'
    rule_path.write_text(yaml.safe_dump(config), encoding='utf-8')
    engine = FlowEngine(RuleRegistry(rule_path))
    conditional, _ = engine.analyze(result.program, set(), Cancellation(), include_boundary_roots=False)
    assert len(conditional) == 12
    assert all(f.validation['required_conditions'] == 'MET' for f in conditional)
    assert engine.stats['required_condition_observations']['MET'] >= 12
    crypto = [f for f in result.findings if f.rule_id in ('AOS-CRYPTO-003', 'AOS-CRYPTO-004')]
    assert len(crypto) == 5
    assert all('->positive(' in f.location.method and f.type == 'REVIEW' for f in crypto)
    assert sum(f.rule_id == 'AOS-CRYPTO-003' for f in crypto) == 3
    material = [f for f in result.findings if f.rule_id in ('AOS-CRYPTO-005', 'AOS-CRYPTO-006')]
    assert len(material) == 3
    assert all(any(name in f.location.method for name in ('->positive(', '->base64Positive('))
               and len(f.data_flow) == 4 for f in material)
    assert all('fixture-key-only' not in repr(f) and 'fixture-iv-only!' not in repr(f) for f in material)
    salt = [f for f in result.findings if f.rule_id == 'AOS-CRYPTO-007']
    assert len(salt) == 1 and '->saltPositive(' in salt[0].location.method
    assert 'fixture-salt-only' not in repr(salt[0]) and len(salt[0].data_flow) == 4
    pending = [f for f in result.findings if f.rule_id in ('AOS-IPC-005', 'AOS-IPC-006')]
    assert len(pending) == 4
    assert {f.rule_id for f in pending} == {'AOS-IPC-005', 'AOS-IPC-006'}
    assert all(any('->' + name + '(' in f.location.method for name in
                   ('implicit', 'conflict', 'cleared', 'copyUnrestricted')) for f in pending)
    assert all(f.type == 'REVIEW' and f.verification == 'MANUAL_REVIEW' for f in pending)
    downloads = [f for f in result.findings if f.rule_id == 'AOS-DYNAMIC-003']
    assert len(downloads) == 2
    assert all(f.type == 'REVIEW' and f.verification == 'MANUAL_REVIEW' and not f.attack_path for f in downloads)
    assert all('->positive(' in f.location.method or '->load(' in f.location.method for f in downloads)
    assert any(f.analysis_level == 'L4' for f in downloads)
    assert sum(result.provenance[key]['steps'] for key in
               ('flow_coverage', 'sensitive_flow_coverage', 'download_flow_coverage')) <= settings.max_flow_steps
    output = tmp_path / 'result.json'
    save_project(output, result)
    reopened = open_project(output)
    assert reopened.program.class_interfaces == result.program.class_interfaces
    assert {f.id for f in reopened.findings} == {f.id for f in result.findings}
