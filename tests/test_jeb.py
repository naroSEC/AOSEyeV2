import os
from pathlib import Path
import pytest
import subprocess
from analyzer.app.jobs import Cancellation
from analyzer.app.settings import Settings
from analyzer.backends.jeb.backend import JebBackend
from analyzer.app.application import AnalysisApplication


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_real_dex_explicit_icc_and_runnable_capture():
    fixture = Path(__file__).resolve().parents[1] / 'build/fixtures/boundary-fixture.apk'
    if not fixture.exists():
        pytest.skip('Run python tools/build_fixture.py first')
    with JebBackend(Settings(cache_enabled=False)) as backend:
        result = AnalysisApplication(backend.settings, backend).analyze(fixture, Cancellation())
        assert not result.program.diagnostics
        assert any(i.opcode == 'const-class' and i.literal == 'Ltest/BoundaryDestination;'
                   for m in result.program.methods.values() for i in m.instructions)
        for kind, destination in [('ASYNC', 'BoundaryTask;->run()'), ('ICC', 'BoundaryDestination;->onCreate(')]:
            findings = [f for f in result.findings if destination in f.location.method
                        and any(kind + ' boundary' in s['label'] for s in f.data_flow)]
            assert findings, (kind, result.diagnostics)
            assert all(f.analysis_level == 'L5' and f.verification == 'POTENTIAL' for f in findings)
        assert not result.complete  # Explicitly disclose unresolved runtime scheduling/lifecycle.


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires installed Jython/JEB libraries')
def test_jython_java_return_preserves_unpaired_surrogates():
    from analyzer.backends.jeb.protocol import decode_java_text
    import json
    settings = Settings()
    java = str(Path(os.environ['JAVA_HOME']) / 'bin/java.exe') if os.environ.get('JAVA_HOME') else settings.java
    bridge = Path(__file__).resolve().parents[1] / 'src/analyzer/backends/jeb/scripts'
    script = ("import sys,json; sys.path.insert(0,sys.argv[1]); "
              "from AOSEyeBridge import java_text_call; from java.lang import StringBuilder; "
              "b=StringBuilder(); b.appendCodePoint(65); b.appendCodePoint(55296); "
              "b.appendCodePoint(128512); print(json.dumps(java_text_call(b,'toString')))")
    completed = subprocess.run([java, '-cp', str(Path(settings.jeb_path) / 'bin/app/*'),
                                'org.python.util.jython', '-c', script, str(bridge)],
                               capture_output=True, text=True, check=True, timeout=30)
    assert json.loads(completed.stdout, object_hook=decode_java_text) == 'A\ud800\U0001f600'


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Set AOSEYE_RUN_JEB=1 for licensed integration')
def test_real_jeb_probe_and_optional_fixture():
    with JebBackend(Settings(cache_enabled=False)) as backend:
        probe = backend.probe(Cancellation())
        assert probe['status'] == 'Connected'
        assert probe['capabilities']['core'] == probe['capabilities']['engines'] == 'verified'
        fixture = os.environ.get('AOSEYE_TEST_APK')
        if fixture:
            program = backend.load(Path(fixture), Cancellation())
            assert program.methods and not program.diagnostics


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Set AOSEYE_RUN_JEB=1 for licensed integration')
def test_fixture_end_to_end_and_persistent_lifecycle():
    fixture = Path(__file__).resolve().parents[1] / 'build/fixtures/flow-fixture.apk'
    if not fixture.exists():
        pytest.skip('Run python tools/build_fixture.py first')
    cancel = Cancellation()
    with JebBackend(Settings(cache_enabled=False)) as backend:
        backend.probe(cancel)
        process = backend.session.process
        result = AnalysisApplication(backend.settings, backend).analyze(fixture, cancel)
        assert result.complete, result.diagnostics
        program = result.program
        assert len(program.dex_units) == 1
        assert program.fields
        assert program.class_index and program.field_index
        assert all(row['unit'] == program.dex_units[0]['id'] for row in program.class_index + program.field_index)
        assert {row['signature'] for row in program.field_index} == set(program.fields)
        assert len(program.method_index) > len(program.methods)
        assert not list(Path(backend.session._directory.name).glob('*.methods.jsonl'))
        assert any(f.analysis_level == 'L5' and f.source.startswith('Landroid/content/Intent;') for f in result.findings)
        assert not any(f.type == 'VULNERABILITY' and 'safe()' in str(f.data_flow) for f in result.findings)
        assert any(f.rule_id == 'AOS-WEBVIEW-005' and 'WebContent;->html(' in f.location.method
                   for f in result.findings)
        assert any(f.rule_id == 'AOS-WEBVIEW-006' and 'WebContent;->script(' in f.location.method
                   for f in result.findings)
        assert not any(f.type == 'VULNERABILITY' and 'historyOnly(' in f.location.method
                       for f in result.findings)
        method = 'Ltest/Main;->onCreate(Landroid/os/Bundle;)V'
        helper = 'Ltest/Navigation;->open(Ljava/lang/String;)V'
        assert backend.get_method_bytecode(method)
        assert backend.get_cfg(method)
        assert helper in backend.get_callees(method)
        assert method in backend.get_callers(helper)
        assert backend.get_call_graph(method)['edges']
        from analyzer.analyzers.url_validation import url_guard_review
        for name, expected in [('exact', 'MODELED_EXACT_MATCH'), ('prefix', 'UNKNOWN'), ('replaced', 'UNKNOWN'),
                               ('helper', 'MODELED_EXACT_MATCH'), ('helperOther', 'UNKNOWN'),
                               ('helperCatchOpen', 'UNKNOWN'), ('helperCatchClosed', 'MODELED_EXACT_MATCH'), ('callerCatch', 'UNKNOWN')]:
            guard = next(m for m in program.methods.values() if m.signature.startswith('Ltest/UrlGuards;->' + name + '('))
            sink = next(i for i in guard.instructions if i.target == 'Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V')
            review = url_guard_review(program, guard.signature, sink.offset, cancel)
            assert review['host_allowlist'] == expected, review
            assert review['scheme_allowlist'] == expected, review
        for name in ('failOpen', 'failClosed', 'callerCatch'):
            guard = next(m for m in program.methods.values() if m.signature.startswith('Ltest/UrlGuards;->' + name + '('))
            assert guard.exception_status == 'PRESENT'
            assert guard.exception_regions and all(i.normal_successors is not None for i in guard.instructions)
            offsets = {i.offset for i in guard.instructions}
            assert all(r['start'] in offsets and r['end'] in offsets for r in guard.exception_regions)
            assert all(h['address'] in offsets for r in guard.exception_regions for h in r['handlers'])
        refs = backend.get_jeb_xrefs(helper, cancel)
        assert refs['total'] == 2
        assert all(r['target_validation'] == 'EXACT_DECLARED_TARGET' for r in refs['items'])
        assert any(r['address'] == method + '+14h' for r in refs['items'])
        from analyzer.core.navigation import native_reference_page, bytecode_location
        checked, links = native_reference_page(program, helper, refs, cancel)
        assert len(links) == 2 and all(item['navigation_allowed'] for item in checked['items'])
        for link in links:
            location, text = bytecode_location(program, link['method'], link['offset'], link['unit'])
            assert location['offset'] == link['offset'] and '>>>' in text
        page = backend.get_jeb_xrefs(helper, cancel, offset=1, limit=1)
        assert page['total'] == 2 and len(page['items']) == 1
        field_refs = backend.get_jeb_xrefs('Ltest/Navigation;->last:Ljava/lang/String;', cancel)
        assert field_refs['total'] >= 1
        source = backend.get_decompiled_source(method, cancel)
        assert 'getStringExtra' in source and 'Navigation.open' in source
        ast = backend.get_ast(method, cancel)
        assert not ast['truncated']
        assert any(n.get('target') == helper and n['offset'] == 20 for n in ast['nodes'])
        assert all(n['offset'] is None or n['offset'] >= 0 for n in ast['nodes'])
        conditional = program.methods['Ltest/Navigation;->conditional(Ljava/lang/String;Z)V']
        assert len(conditional.cfg) >= 2
        ranged = program.methods['Ltest/Navigation;->rangeCall(Ljava/lang/String;)V']
        assert any(i.opcode == 'invoke-static/range' and len(i.registers) == 6 for i in ranged.instructions)
        assert backend.session_info['project_generation'] == 1
        assert backend.session.process is process
        for capability in ('core', 'engines', 'dex', 'cfg', 'xrefs', 'decompiler', 'ast'):
            assert backend.capabilities[capability] == 'verified'
        # Switch inputs and ensure the old project is released, while the JVM stays.
        backend.load(fixture.with_name('classes.dex'), cancel)
        assert backend.session_info['project_generation'] == 2
        assert backend.session.process is process
    assert process.poll() == 0
    assert backend.session.pid is None
