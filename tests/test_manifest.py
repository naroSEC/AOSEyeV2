from analyzer.analyzers.manifest import analyze_manifest, external_entries
from conftest import ENTRY
import pytest
from analyzer.analyzers.manifest import entry_catalog


def manifest(body, sdk=30, app=''):
    return f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test"><uses-sdk android:targetSdkVersion="{sdk}"/><application {app}>{body}</application></manifest>'


def test_exported_is_exposure_not_vulnerability(flow_program):
    info, findings = analyze_manifest(manifest('<activity android:name=".Main" android:exported="true"/>'))
    exposure = next(f for f in findings if f.category == 'COMPONENT')
    assert exposure.type == 'EXPOSURE' and exposure.severity == 'INFO'
    assert external_entries(info, flow_program.methods) == {ENTRY}


def test_application_permission_inherited(flow_program):
    info, _ = analyze_manifest(manifest('<activity android:name=".Main" android:exported="true"/>', app='android:permission="test.SIGNATURE"'))
    assert not external_entries(info, flow_program.methods)


def test_modern_missing_exported_is_unknown():
    info, _ = analyze_manifest(manifest('<activity android:name=".Main"><intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter></activity>', 31))
    assert info['components'][0]['exported'] is None


def test_provider_default_by_target_sdk():
    old, _ = analyze_manifest(manifest('<provider android:name=".Provider"/>', 16))
    modern, _ = analyze_manifest(manifest('<provider android:name=".Provider"/>', 17))
    assert old['components'][0]['exported'] is True
    assert modern['components'][0]['exported'] is False


def test_disabled_not_external(flow_program):
    info, _ = analyze_manifest(manifest('<activity android:name=".Main" android:exported="true" android:enabled="false"/>'))
    assert not external_entries(info, flow_program.methods)


def test_alias_entry_and_deep_link(flow_program):
    info, _ = analyze_manifest(manifest('<activity-alias android:name=".Alias" android:targetActivity=".Main" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><data android:scheme="demo" android:host="open"/></intent-filter></activity-alias>'))
    assert external_entries(info, flow_program.methods) == {ENTRY}
    assert info['deep_links'][0]['data'][0]['scheme'] == 'demo'


def test_callback_name_alone_does_not_establish_entry(flow_program):
    item = flow_program.methods.pop(ENTRY)
    item.signature = 'Ltest/Main;->onCreate(Ljava/lang/String;)V'
    flow_program.methods[item.signature] = item
    info, _ = analyze_manifest(manifest('<activity android:name=".Main" android:exported="true"/>'))
    assert not external_entries(info, flow_program.methods)


@pytest.mark.parametrize('component,application,expected', [
    ('@bool/component_enabled', '', None), ('true', 'android:enabled="@bool/app_enabled"', None),
    ('false', 'android:enabled="@bool/app_enabled"', False),
    ('@bool/component_enabled', 'android:enabled="false"', False), ('true', '', True)])
def test_enabled_is_three_valued(component, application, expected):
    info, _ = analyze_manifest(manifest(
        f'<activity android:name=".Main" android:exported="true" android:enabled="{component}"/>', app=application))
    assert info['components'][0]['enabled'] is expected
    if expected is None:
        assert info['diagnostics']


@pytest.mark.parametrize('attribute', ['android:enabled="@bool/enabled"',
                                      'android:permission="@string/permission"',
                                      'android:exported="@bool/exported"'])
def test_unknown_configuration_is_possible_not_confirmed(flow_program, attribute):
    exported = '' if 'exported=' in attribute else 'android:exported="true"'
    info, _ = analyze_manifest(manifest(f'<activity android:name=".Main" {exported} {attribute}/>'))
    catalog = entry_catalog(info, flow_program.methods)
    assert catalog['uncertain'] == [ENTRY] and not catalog['confirmed']
    assert not external_entries(info, flow_program.methods)


def test_inherited_lifecycle_shared_with_reviewer(flow_program):
    from analyzer.analyzers.verification import CandidateReviewer
    base = ENTRY.replace('Main', 'Base')
    m = flow_program.methods.pop(ENTRY); m.signature=base; m.class_name='Ltest/Base;'
    flow_program.methods[base]=m
    flow_program.class_hierarchy={'Ltest/Main;':'Ltest/Base;'}
    info, _=analyze_manifest(manifest('<activity android:name=".Main" android:exported="true"/>'))
    catalog=entry_catalog(info,flow_program.methods,flow_program.class_hierarchy)
    reviewer=CandidateReviewer(flow_program,info)
    assert set(catalog['confirmed'])==reviewer.entries=={base}
    assert catalog['records'][0]['inherited']


def test_local_override_stops_inherited_callback(flow_program):
    from conftest import method
    from analyzer.core.models import Instruction
    base=ENTRY.replace('Main','Base')
    flow_program.methods[base]=method(base,[Instruction(0,'return-void')])
    flow_program.class_hierarchy={'Ltest/Main;':'Ltest/Base;'}
    info,_=analyze_manifest(manifest('<activity android:name=".Main" android:exported="true"/>'))
    assert external_entries(info,flow_program.methods,flow_program.class_hierarchy)=={ENTRY}


def test_native_override_without_body_does_not_fall_back(flow_program):
    base=ENTRY.replace('Main','Base')
    flow_program.methods[base]=flow_program.methods.pop(ENTRY)
    flow_program.class_hierarchy={'Ltest/Main;':'Ltest/Base;'}
    info,_=analyze_manifest(manifest('<activity android:name=".Main" android:exported="true"/>'))
    catalog=entry_catalog(info,flow_program.methods,flow_program.class_hierarchy,
                          [{'signature':ENTRY,'declared':True,'has_code':False}])
    assert not catalog['confirmed'] and catalog['diagnostics']


def test_cyclic_hierarchy_terminates(flow_program):
    info,_=analyze_manifest(manifest('<activity android:name=".Other" android:exported="true"/>'))
    catalog=entry_catalog(info,flow_program.methods,{'Ltest/Other;':'Ltest/Other;'})
    assert not catalog['confirmed'] and any('cycle' in d for d in catalog['diagnostics'])


def test_alias_does_not_inherit_application_permission(flow_program):
    info,_=analyze_manifest(manifest('<activity android:name=".Main" android:exported="false"/>'
        '<activity-alias android:name=".Alias" android:targetActivity=".Main" android:exported="true"/>',
        app='android:permission="test.SIGNATURE"'))
    assert external_entries(info,flow_program.methods)=={ENTRY}


def test_legacy_index_cannot_prove_absence_of_native_override(flow_program):
    base = ENTRY.replace('Main', 'Base')
    flow_program.methods[base] = flow_program.methods.pop(ENTRY)
    info, _ = analyze_manifest(manifest('<activity android:name=".Main" android:exported="true"/>'))
    catalog = entry_catalog(info, flow_program.methods, {'Ltest/Main;': 'Ltest/Base;'},
                            [{'signature': ENTRY, 'has_code': False}])
    assert not catalog['uncertain'] and not catalog['confirmed']
    assert any(item['resolution'] == 'UNKNOWN_DECLARATION' for item in catalog['records'])
    assert any('reindex required' in item for item in catalog['diagnostics'])
