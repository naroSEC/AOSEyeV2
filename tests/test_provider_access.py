import pytest
from analyzer.analyzers.manifest import analyze_manifest, entry_catalog, LIFECYCLE_SIGNATURES
from analyzer.core.models import Method


@pytest.mark.parametrize('attributes,read,write', [
    ('android:writePermission="test.WRITE"', 'NONE', 'REQUIRED'),
    ('android:readPermission="test.READ"', 'REQUIRED', 'NONE'),
    ('android:permission="test.BASE" android:readPermission=""', 'NONE', 'REQUIRED'),
    ('android:readPermission="@string/read"', 'UNKNOWN', 'NONE'),
    ('', 'NONE', 'NONE'),
])
def test_operation_specific_entries(attributes, read, write):
    xml = '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test"><application><provider android:name=".Provider" android:exported="true" ' + attributes + '/></application></manifest>'
    info, _ = analyze_manifest(xml)
    policy = info['components'][0]['access_policy']
    assert policy['operations']['read']['state'] == read
    assert policy['operations']['write']['state'] == write
    methods = {}
    for member in LIFECYCLE_SIGNATURES['provider']:
        sig = 'Ltest/Provider;->' + member
        methods[sig] = Method(signature=sig)
    catalog = entry_catalog(info, methods)
    for sig in methods:
        member = sig.split('->')[1]
        state = 'UNKNOWN' if member.startswith(('openFile(', 'call(')) else read if member.startswith('query(') else write
        assert (sig in catalog['confirmed']) == (state == 'NONE')
        assert (sig in catalog['uncertain']) == (state == 'UNKNOWN')


def test_path_rules_and_application_inheritance():
    xml = '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test"><application android:permission="test.APP"><provider android:name=".Provider" android:exported="true"><path-permission android:pathPrefix="/public" android:readPermission="test.OTHER"/></provider></application></manifest>'
    info, _ = analyze_manifest(xml)
    component = info['components'][0]
    assert component['access_policy']['operations']['read']['permission'] == 'test.APP'
    sig = 'Ltest/Provider;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;'
    catalog = entry_catalog(info, {sig: Method(signature=sig)})
    assert catalog['uncertain'] == [sig] and not catalog['confirmed']
