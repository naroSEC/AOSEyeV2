"""Compiled local fixture; never installed, signed, or executed on a device."""
import os
from pathlib import Path
import subprocess
from zipfile import ZipFile

import pytest

from analyzer.app.jobs import Cancellation
from analyzer.analyzers.storage_config import parse_rules


@pytest.mark.parametrize('kind,xml', [
    ('unknown', '<data-extraction-rules/>'),
    ('dataExtractionRules', '<data-extraction-rules><full-backup-content/></data-extraction-rules>'),
    ('dataExtractionRules', '<data-extraction-rules><cloud-backup/><cloud-backup/></data-extraction-rules>'),
    ('fullBackupContent', '<full-backup-content><include domain="unknown" path="."/></full-backup-content>'),
    ('fullBackupContent', '<full-backup-content><include domain="file"/></full-backup-content>'),
])
def test_invalid_backup_structure(kind, xml):
    with pytest.raises(ValueError):
        parse_rules(xml.encode(), kind, Cancellation())


@pytest.mark.jeb
@pytest.mark.skipif(os.environ.get('AOSEYE_RUN_JEB') != '1', reason='Requires licensed JEB')
def test_compiled_backup_pipeline_and_roundtrip(tmp_path):
    from analyzer.app.settings import Settings
    from analyzer.app.application import AnalysisApplication
    from analyzer.app.project_manager import save_project, open_project, write_json
    from analyzer.backends.jeb.backend import JebBackend
    from analyzer.analyzers.storage_config import analyze_storage_config
    root = Path(__file__).resolve().parents[1]
    aapt = Path(os.environ.get('AOSEYE_TEST_AAPT2', 'missing'))
    if not aapt.is_file():
        pytest.skip('Set AOSEYE_TEST_AAPT2 to local aapt2')
    android = Path(os.environ.get('AOSEYE_TEST_ANDROID_JAR', str(aapt.parents[2] / 'platforms/android-35/android.jar')))
    dex = root / 'build/fixtures/classes.dex'
    if not android.is_file() or not dex.is_file():
        pytest.skip('Requires Android platform jar and tools/build_fixture.py output')
    fixture = root / 'tests/fixtures/backup'
    resources, apk = tmp_path / 'resources.zip', tmp_path / 'backup.apk'
    for command in ([aapt, 'compile', '--dir', fixture / 'res', '-o', resources],
                    [aapt, 'link', '-I', android, '--manifest', fixture / 'AndroidManifest.xml', '-o', apk, resources]):
        subprocess.run(list(map(str, command)), check=True, capture_output=True, timeout=60)
    with ZipFile(apk, 'a') as archive:
        archive.write(dex, 'classes.dex')
    settings = Settings(jvm_heap_mib=1024, aapt2_path=str(aapt))
    token = Cancellation()
    with JebBackend(settings) as backend:
        result = AnalysisApplication(settings, backend).analyze(apk, token)
        inventory = result.manifest['storage_config']
        rows = inventory['resources']
        assert len(rows) == 2 and all(r['status'] == 'PARSED_DECLARATIONS' for r in rows)
        legacy, modern = rows
        assert legacy['kind'] == 'fullBackupContent' and modern['kind'] == 'dataExtractionRules'
        assert legacy['transports'][0]['rules'][0]['requireFlags'] == 'clientSideEncryption'
        cloud, device = modern['transports']
        assert cloud['transport'] == 'cloud-backup' and device['transport'] == 'device-transfer'
        assert cloud['attributes']['disableIfNoEncryptionCapabilities'] == 'true'
        assert cloud['selection'] == 'explicit-includes'
        assert device['selection'] == 'platform-default-minus-excludes'
        assert all(r['configuration'] == 'default-only' for r in rows)
        assert any('Storage XML default configuration only' in d for d in result.diagnostics)
        # Independently exercise numeric references against the same resource table.
        table = backend._run('resources', token, **backend._input_request(token))
        ids = {r['path']: r['id'] for r in table['resources']}
        numeric = dict(application={r['kind']: '@%08x' % ids[r['resource']] for r in rows})
        mapped, _, _ = analyze_storage_config(apk, numeric, token, backend.resolve_network_xml)
        assert [r['transports'] for r in mapped['resources']] == [r['transports'] for r in rows]
    project = tmp_path / 'project.json'
    save_project(project, result)
    assert open_project(project).manifest['storage_config'] == inventory
    write_json(root / 'build/compiled-backup-validation.json', dict(input_sha256=result.sha256,
        inventory=inventory, numeric_matches=True, project_roundtrip=True,
        scope='Generated unsigned fixture only; APK not installed or executed'))
