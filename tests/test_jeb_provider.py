"""JDK/D8/aapt2 generated fixture, licensed JEB evidence; no APK execution."""
import os
from pathlib import Path
import subprocess
from zipfile import ZipFile
import pytest


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_real_provider_operation_permissions(tmp_path):
    from analyzer.app.application import AnalysisApplication
    from analyzer.app.settings import Settings
    from analyzer.app.jobs import Cancellation
    from analyzer.app.project_manager import save_project, open_project, write_json
    from analyzer.backends.jeb.backend import JebBackend
    from analyzer.gui.review import review_view
    import json
    aapt = Path(os.environ.get('AOSEYE_TEST_AAPT2', 'missing'))
    if not aapt.is_file():
        pytest.skip('Set AOSEYE_TEST_AAPT2')
    android = Path(os.environ.get('AOSEYE_TEST_ANDROID_JAR', str(aapt.parents[2] / 'platforms/android-35/android.jar')))
    if not android.is_file():
        pytest.skip('Android platform jar unavailable')
    root = Path(__file__).resolve().parents[1]
    settings = Settings(jvm_heap_mib=1024, cache_enabled=False)
    classes, dex = tmp_path / 'classes', tmp_path / 'dex'
    classes.mkdir()
    dex.mkdir()
    def run(command):
        completed = subprocess.run(list(map(str, command)), capture_output=True, timeout=60)
        assert completed.returncode == 0, completed.stderr.decode('utf-8', errors='replace')
    run(['javac', '--release', '8', '-cp', android, '-d', classes,
         root / 'tests/fixtures/provider/ProviderFixture.java'])
    run([settings.java, '-cp', Path(settings.jeb_path) / 'bin/app/d8.jar', 'com.android.tools.r8.D8',
         '--min-api', '23', '--lib', android, '--output', dex, classes / 'test/ProviderFixture.class'])
    records = []
    with JebBackend(settings) as backend:
        for case, attributes, child in [
            ('write_required', 'android:writePermission="test.WRITE"', ''),
            ('read_required', 'android:readPermission="test.READ"', ''),
            ('path_unknown', '', '<path-permission android:pathPrefix="/private" android:readPermission="test.READ"/>'),
        ]:
            manifest = tmp_path / (case + '.xml')
            manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.providerfixture">'
                '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><application>'
                '<provider android:name="test.ProviderFixture" android:authorities="test.fixture" android:exported="true" '
                + attributes + '>' + child + '</provider></application></manifest>', encoding='utf-8')
            apk = tmp_path / (case + '.apk')
            run([aapt, 'link', '-I', android, '--manifest', manifest, '-o', apk])
            with ZipFile(apk, 'a') as archive:
                archive.write(dex / 'classes.dex', 'classes.dex')
            result = AnalysisApplication(settings, backend).analyze(apk, Cancellation())
            flows = [f for f in result.findings if f.data_flow]
            def at(name):
                return [f for f in flows if '->' + name + '(' in f.location.method]
            assert bool(at('query')) == (case != 'read_required')
            assert bool(at('update')) == (case != 'write_required')
            assert len(at('update')) == (0 if case == 'write_required' else 3)
            if at('update'):
                assert sum(any(s['label'] == 'HashMap replace previous value' for s in f.data_flow) for f in at('update')) == 1
                assert any(i.target == 'Ljava/util/Map;->replace(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;'
                           for i in result.program.methods[at('update')[0].location.method].instructions)
            for finding in at('query'):
                assert any(step['label'] == 'ArrayList clone index 0' for step in finding.data_flow)
                assert any(step['label'] == 'ArrayList constructor copy index 0' for step in finding.data_flow)
                instructions = result.program.methods[finding.location.method].instructions
                for target in ('Ljava/util/ArrayList;-><init>(I)V', 'Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V'):
                    assert any(i.opcode.startswith('invoke-direct') and i.target == target for i in instructions)
                assert sum(step['label'] == 'ArrayList addAll index 0 -> 0' for step in finding.data_flow) == 2
                assert any('array read index 0' in step['label'] for step in finding.data_flow)
                assert any('System.arraycopy index 0 -> 0' in step['label'] for step in finding.data_flow)
            assert len(at('query')) == (0 if case == 'read_required' else 12)
            if at('query'):
                assert any(i.opcode == 'mul-int/lit8' and i.literal == 3
                           for i in result.program.methods['Ltest/ProviderFixture;->tripleSize([Ljava/lang/Object;)I'].instructions)
                assert any(i.opcode == 'sub-int/2addr' for i in result.program.methods[at('query')[0].location.method].instructions)
                assert any(i.opcode == 'add-int/lit8' and i.literal == -1
                           for i in result.program.methods['Ltest/ProviderFixture;->lastIndex([Ljava/lang/Object;)I'].instructions)
                assert any(i.opcode == 'array-length' for i in result.program.methods['Ltest/ProviderFixture;->arraySize([Ljava/lang/Object;)I'].instructions)
                assert any(i.target == 'Ltest/ProviderFixture;->arraySize([Ljava/lang/Object;)I'
                           for i in result.program.methods[at('query')[0].location.method].instructions)
                assert sum(any(s['label'] == 'Collections.swap index 0 -> 1' for s in f.data_flow) for f in at('query')) == 11
                assert sum(any(s['label'] == 'Collections.reverse index 0 -> 2' for s in f.data_flow) for f in at('query')) == 10
                assert sum(any(s['label'] == 'Collections.rotate index 0 -> 1' for s in f.data_flow) for f in at('query')) == 9
                assert sum(any(s['label'] == 'Collections.rotate index 1 -> 0' for s in f.data_flow) for f in at('query')) == 8
                assert sum(any(s['label'] == 'Arrays.fill range index 0' for s in f.data_flow) for f in at('query')) == 2
                assert any(i.opcode.startswith('invoke-static') and i.target == 'Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V'
                           for i in result.program.methods[at('query')[0].location.method].instructions)
                assert sum(any(s['label'] == 'Arrays.fill index 2' for s in f.data_flow) for f in at('query')) == 2
                assert any(i.opcode.startswith('invoke-static') and i.target == 'Ljava/util/Arrays;->fill([Ljava/lang/Object;Ljava/lang/Object;)V'
                           for i in result.program.methods[at('query')[0].location.method].instructions)
                assert sum(any(s['label'] == 'Collections.addAll array index 0 -> 2' for s in f.data_flow) for f in at('query')) == 1
                assert any(i.opcode.startswith('invoke-static') and i.target == 'Ljava/util/Collections;->addAll(Ljava/util/Collection;[Ljava/lang/Object;)Z'
                           for i in result.program.methods[at('query')[0].location.method].instructions)
                assert sum(any(s['label'] == 'Collections.copy index 0' for s in f.data_flow) for f in at('query')) == 1
                assert any(i.opcode.startswith('invoke-static') and i.target == 'Ljava/util/Collections;->copy(Ljava/util/List;Ljava/util/List;)V'
                           for i in result.program.methods[at('query')[0].location.method].instructions)
                assert sum(any(s['label'] == 'Collections.fill index 1' for s in f.data_flow) for f in at('query')) == 1
                assert any(i.opcode.startswith('invoke-static') and i.target == 'Ljava/util/Collections;->fill(Ljava/util/List;Ljava/lang/Object;)V'
                           for i in result.program.methods[at('query')[0].location.method].instructions)
                assert any(i.opcode.startswith('invoke-static') and i.target == 'Ljava/util/Collections;->rotate(Ljava/util/List;I)V'
                           for i in result.program.methods[at('query')[0].location.method].instructions)
                assert any(i.opcode.startswith('invoke-static') and i.target == 'Ljava/util/Collections;->reverse(Ljava/util/List;)V'
                           for i in result.program.methods[at('query')[0].location.method].instructions)
                assert any(i.opcode.startswith('invoke-static') and i.target == 'Ljava/util/Collections;->swap(Ljava/util/List;II)V'
                           for i in result.program.methods[at('query')[0].location.method].instructions)
                assert sum(any(s['label'] == 'ArrayList iterator next index 0' for s in f.data_flow) for f in at('query')) == 1
                assert any(i.target == 'Ljava/util/Iterator;->remove()V' for i in result.program.methods[at('query')[0].location.method].instructions)
            for finding in at('update'):
                assert any(step['label'] in ('HashMap get', 'HashMap getOrDefault default', 'HashMap replace previous value') for step in finding.data_flow)
                if any(step['label'] in ('HashMap get', 'HashMap replace previous value') for step in finding.data_flow):
                    assert any(step['label'] == 'HashMap constructor copy' for step in finding.data_flow)
                    assert any(step['label'] == 'HashMap clone' for step in finding.data_flow)
                    assert any(i.target == 'Ljava/util/HashMap;-><init>(I)V' for i in result.program.methods[finding.location.method].instructions)
                    assert any(step['label'] == 'HashMap putAll' for step in finding.data_flow)
                assert any(step['label'] == 'Arrays.copyOf index 0' for step in finding.data_flow)
                assert any(step['label'] == 'array clone' for step in finding.data_flow)
                assert any(step['label'] in ('filled array index 0', 'array write index 0') for step in finding.data_flow)
                assert any(i.target == '[Ljava/lang/String;->clone()Ljava/lang/Object;' for i in result.program.methods[finding.location.method].instructions)
            for finding in at('openFile'):
                assert any(step['label'] == 'ArrayList insert shift 0 -> 1' for step in finding.data_flow)
                assert any(step['label'] == 'ArrayList remove shift 1 -> 0' for step in finding.data_flow)
                assert any(step['label'] in ('ArrayList get index 0', 'ArrayList toArray index 0') for step in finding.data_flow)
                assert any('filled array index 0' in step['label'] for step in finding.data_flow)
                assert any(i.opcode == 'filled-new-array' for i in result.program.methods[finding.location.method].instructions)
            assert len(at('openFile')) == 2
            assert sum(any(s['label'] == 'ArrayList toArray index 0' for s in f.data_flow) for f in at('openFile')) == 1
            for finding in at('call'):
                assert any(i.opcode == 'filled-new-array/range' for i in result.program.methods[finding.location.method].instructions)
                assert any('filled array index 1' in step['label'] for step in finding.data_flow)
                assert any(step['label'] == 'Arrays.copyOfRange index 1 -> 0' for step in finding.data_flow)
                assert any(step['label'] in ('ArrayList get index 0', 'ArrayList remove index 0', 'ArrayList toArray argument index 0') for step in finding.data_flow)
                instructions = result.program.methods[finding.location.method].instructions
                for target in ('Ljava/util/Collection;->add(Ljava/lang/Object;)Z',
                               'Ljava/util/Collection;->toArray()[Ljava/lang/Object;',
                               'Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;',
                               'Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;',
                               'Ljava/util/Collection;->clear()V',
                               'Ljava/util/List;->get(I)Ljava/lang/Object;',
                               'Ljava/util/List;->remove(I)Ljava/lang/Object;',
                               'Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;'):
                    assert any(i.opcode.startswith('invoke-interface') and i.target == target for i in instructions)
            assert len(at('call')) == 4
            assert sum(any(s['label'] == 'ArrayList toArray argument index 0' for s in f.data_flow) for f in at('call')) == 2
            assert sum(any(s['label'] == 'ArrayList remove index 0' for s in f.data_flow) for f in at('call')) == 1
            for name in ('query', 'update', 'openFile', 'call'):
                for finding in at(name):
                    uncertain = case == 'path_unknown' or name in ('openFile', 'call')
                    assert finding.verification == ('POTENTIAL' if uncertain else 'LIKELY')
                    assert finding.analysis_level == ('L3' if uncertain else 'L5')
                    assert bool(finding.attack_path) != uncertain
                    assert finding.review['reachability']['paths'][0]['configuration_uncertain'] == uncertain
                    method = result.program.methods[finding.location.method]
                    assert any(i.offset == finding.location.offset and i.target == finding.sink for i in method.instructions)
                    _, content, _ = review_view(result.program, finding, Cancellation())
                    assert json.loads(content)['saved_candidate_review'] == finding.review
            assert at('openFile') and at('call')
            project = tmp_path / (case + '.json')
            save_project(project, result)
            assert open_project(project).to_dict() == result.to_dict()
            records.append(dict(case=case, sha256=result.sha256, entrypoints=result.provenance['entrypoints'],
                                flows=flows, diagnostics=result.diagnostics, roundtrip=True))
    write_json(root / 'build/jeb-provider-validation.json', dict(cases=records,
        scope='Generated unsigned APKs; actual JEB DEX extraction and analysis, not runtime access proof'))
