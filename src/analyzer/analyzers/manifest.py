from defusedxml import ElementTree as ET
from analyzer.core.models import Finding, Location

A = '{http://schemas.android.com/apk/res/android}'


def boolean_value(value, default=True):
    if value is None:
        return default
    return True if value == 'true' else False if value == 'false' else None


def enabled_value(component, application):
    values = (boolean_value(component), boolean_value(application))
    return False if False in values else None if None in values else True


def permission_state(value):
    if value == '':
        return 'NONE'
    if not isinstance(value, str) or value.startswith(('@', '?')):
        return 'UNKNOWN'
    return 'REQUIRED'


def provider_access(component):
    """Base declarations only; path rules, URI grants and implementation checks remain separate."""
    attrs = component.get('attributes', {})
    base = component.get('permission', '')
    operations = {}
    for operation, key in (('read', 'readPermission'), ('write', 'writePermission')):
        value = attrs.get(key, base)
        operations[operation] = dict(permission=value, state=permission_state(value),
                                    origin=key if key in attrs else 'component/application permission')
    return dict(operations=operations, path_rules=component.get('path_permissions', []),
                grant_rules=component.get('grant_uri_permissions', []),
                grant_uri_permissions=boolean_value(attrs.get('grantUriPermissions'), False),
                limitation='Base declarations only; not URI matching, grant possession, permission strength or runtime access proof')


def provider_entry_state(component, member):
    access = provider_access(component)
    # Paths may introduce alternatives. openFile requires a runtime mode; call
    # permissions are implementation-defined. Never label these as unprotected.
    if access['path_rules'] or member.startswith(('openFile(', 'call(')):
        return 'UNKNOWN'
    operation = 'read' if member.startswith('query(') else 'write'
    return access['operations'][operation]['state']
CALLBACKS = {'activity': {'onCreate', 'onNewIntent'}, 'activity-alias': {'onCreate', 'onNewIntent'},
             'service': {'onStartCommand', 'onBind', 'onHandleIntent'}, 'receiver': {'onReceive'},
             'provider': {'query', 'insert', 'update', 'delete', 'openFile', 'call'}}
LIFECYCLE_SIGNATURES = {
    'activity': {'onCreate(Landroid/os/Bundle;)V',
                 'onCreate(Landroid/os/Bundle;Landroid/os/PersistableBundle;)V',
                 'onNewIntent(Landroid/content/Intent;)V'},
    'service': {'onStartCommand(Landroid/content/Intent;II)I',
                'onBind(Landroid/content/Intent;)Landroid/os/IBinder;',
                'onHandleIntent(Landroid/content/Intent;)V'},
    'receiver': {'onReceive(Landroid/content/Context;Landroid/content/Intent;)V'},
    'provider': {'query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;',
                 'query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;',
                 'insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;',
                 'update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I',
                 'delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I',
                 'openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;',
                 'call(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;'},
}
LIFECYCLE_SIGNATURES['activity-alias'] = LIFECYCLE_SIGNATURES['activity']


def analyze_manifest(xml: str) -> tuple[dict, list[Finding]]:
    root = ET.fromstring(xml)
    package = root.get('package', '')
    sdk = root.find('uses-sdk')
    def sdk_int(key, default):
        value = sdk.get(A + key, str(default)) if sdk is not None else str(default)
        return int(value) if value.isdigit() else None
    minimum = sdk_int('minSdkVersion', 1)
    target = sdk_int('targetSdkVersion', minimum or 1)
    info = dict(package=package, version=root.get(A + 'versionName', ''), min_sdk=minimum,
                target_sdk=target, permissions=[x.get(A + 'name') for x in root.findall('uses-permission')],
                custom_permissions=[], components=[], deep_links=[], application={}, diagnostics=[])
    findings = []
    app = root.find('application')
    if app is None:
        return info, findings
    attrs = {k.removeprefix(A): v for k, v in app.attrib.items()}
    info['application'] = attrs
    for attr, title, severity, typ in [
        ('debuggable', 'Application is debuggable', 'MEDIUM', 'WEAKNESS'),
        ('usesCleartextTraffic', 'Cleartext traffic explicitly permitted', 'LOW', 'WEAKNESS'),
        ('allowBackup', 'Backup configuration requires review', 'INFO', 'REVIEW')]:
        if attrs.get(attr, 'true' if attr == 'allowBackup' else 'false') == 'true':
            if attr == 'usesCleartextTraffic' and 'networkSecurityConfig' in attrs:
                title = 'Manifest cleartext flag requires OS/configuration review'
                severity, typ = 'INFO', 'REVIEW'
            findings.append(Finding('AOS-MANIFEST-' + attr.upper(), title,
                'Manifest configuration; effective behavior can depend on OS, target SDK and resource overrides.',
                'MANIFEST', type=typ, severity=severity, confidence='HIGH', analysis_level='L0',
                location=Location(file='AndroidManifest.xml'), evidence=[f'{attr}={attrs.get(attr, "true (default)")}']))
    for permission in root.findall('permission'):
        name = permission.get(A + 'name', '')
        protection = permission.get(A + 'protectionLevel', 'normal')
        info['custom_permissions'].append(dict(name=name, protection=protection))
        if protection in ('normal', 'dangerous', '0', '1', '0x0', '0x1'):
            findings.append(Finding('AOS-IPC-001', 'Non-signature custom permission',
                'Review whether this permission protects privileged operations.', 'IPC', type='EXPOSURE',
                confidence='HIGH', analysis_level='L0', location=Location(file='AndroidManifest.xml'),
                evidence=[name, protection]))
    def qualified(name):
        return package + name if name.startswith('.') else package + '.' + name if '.' not in name else name
    for item in app:
        if item.tag not in CALLBACKS:
            continue
        attributes = {k.removeprefix(A): v for k, v in item.attrib.items()}
        name = qualified(attributes.get('name', ''))
        explicit = attributes.get('exported')
        filters = item.findall('intent-filter')
        if explicit is not None:
            exported = True if explicit == 'true' else False if explicit == 'false' else None
        elif item.tag == 'provider':
            exported = target <= 16 if target is not None else None
        else:
            exported = None if filters and (target is None or target >= 31) else bool(filters)
        permission = attributes.get('permission', '' if item.tag == 'activity-alias' else attrs.get('permission', ''))
        enabled = enabled_value(attributes.get('enabled'), attrs.get('enabled'))
        unresolved = [field for field, value in [('exported', exported), ('enabled', enabled)] if value is None]
        if permission_state(permission) == 'UNKNOWN':
            unresolved.append('permission')
        if item.tag == 'provider':
            unresolved.extend(key for key in ('readPermission', 'writePermission')
                              if permission_state(attributes.get(key, permission)) == 'UNKNOWN')
        if unresolved:
            info['diagnostics'].append('Unresolved component configuration: ' + name + ': ' + ', '.join(unresolved))
        component = dict(name=name, kind=item.tag, exported=exported, enabled=enabled,
                         permission=permission, permission_state=permission_state(permission),
                         unresolved=unresolved, attributes=attributes,
                         target=qualified(attributes.get('targetActivity', attributes.get('name', ''))),
                         filters=[])
        if item.tag == 'provider':
            component['metadata'] = [{k.removeprefix(A): v for k, v in node.attrib.items()}
                                     for node in item.findall('meta-data')]
            component['path_permissions'] = [{k.removeprefix(A): v for k, v in node.attrib.items()}
                                             for node in item.findall('path-permission')]
            component['grant_uri_permissions'] = [{k.removeprefix(A): v for k, v in node.attrib.items()}
                                                  for node in item.findall('grant-uri-permission')]
            component['access_policy'] = provider_access(component)
        for intent in filters:
            filt = dict(actions=[x.get(A + 'name', '') for x in intent.findall('action')],
                        categories=[x.get(A + 'name', '') for x in intent.findall('category')],
                        auto_verify=intent.get(A + 'autoVerify') == 'true',
                        data=[{k.removeprefix(A): v for k, v in x.attrib.items()} for x in intent.findall('data')])
            component['filters'].append(filt)
            if 'android.intent.action.VIEW' in filt['actions'] and filt['data']:
                info['deep_links'].append(dict(component=name, **filt))
        info['components'].append(component)
        if exported is True and enabled is True:
            findings.append(Finding('AOS-COMPONENT-001', 'Exported ' + item.tag + ': ' + name,
                'Attack surface inventory; exported status alone is not a vulnerability.', 'COMPONENT',
                type='EXPOSURE', confidence='HIGH', analysis_level='L0',
                location=Location(class_name=name, file='AndroidManifest.xml'),
                evidence=['permission=' + (permission or '(none)'), str(attributes)]))
        elif exported is None:
            findings.append(Finding('AOS-COMPONENT-002', 'Unresolved exported configuration: ' + name,
                'Missing or unresolved exported attribute; modern target SDKs require explicit values with intent filters.',
                'COMPONENT', location=Location(file='AndroidManifest.xml', class_name=name), analysis_level='L0'))
        if enabled is None or permission_state(permission) == 'UNKNOWN':
            findings.append(Finding('AOS-COMPONENT-003', 'Unresolved enabled or permission configuration: ' + name,
                'Resource references are not evaluated. This is neither a disabled component nor proven unprotected exposure.',
                'COMPONENT', confidence='LOW', location=Location(file='AndroidManifest.xml', class_name=name),
                analysis_level='L0', evidence=[str(attributes)]))
    return info, findings


def entry_catalog(manifest: dict, methods: dict, hierarchy=None, method_index=()) -> dict:
    """One lifecycle contract for analysis and review; unknown is not disabled."""
    hierarchy = hierarchy or {}
    confirmed, uncertain, records, diagnostics = set(), set(), [], []
    from analyzer.core.models import Program
    from analyzer.core.graph import DeclarationResolver
    resolver = DeclarationResolver(Program(methods=methods, class_hierarchy=hierarchy, method_index=method_index))
    for component in manifest.get('components', []):
        attributes = component.get('attributes', {})
        if component.get('exported') is False or component.get('enabled') is False:
            continue
        permissions = [component.get('permission', '')]
        states = [permission_state(p) for p in permissions]
        if component['kind'] != 'provider' and 'REQUIRED' in states:
            continue
        is_uncertain = (component.get('exported') is not True or component.get('enabled') is not True
                        or 'UNKNOWN' in states)
        descriptor = 'L' + component['target'].replace('.', '/') + ';'
        for member in sorted(LIFECYCLE_SIGNATURES.get(component['kind'], ())):
            entry_uncertain = is_uncertain
            reasons = []
            if component.get('exported') is not True:
                reasons.append('EXPORTED_UNRESOLVED')
            if component.get('enabled') is not True:
                reasons.append('ENABLED_UNRESOLVED')
            if component['kind'] == 'provider':
                state = provider_entry_state(component, member)
                if state == 'REQUIRED':
                    continue
                entry_uncertain = (component.get('exported') is not True or component.get('enabled') is not True
                                   or state == 'UNKNOWN')
                if component.get('path_permissions'):
                    reasons.append('PROVIDER_PATH_PERMISSION_UNRESOLVED')
                if member.startswith('openFile('):
                    reasons.append('PROVIDER_FILE_MODE_UNRESOLVED')
                elif member.startswith('call('):
                    reasons.append('PROVIDER_CALL_CHECKS_UNRESOLVED')
                elif state == 'UNKNOWN' and not component.get('path_permissions'):
                    reasons.append('PROVIDER_OPERATION_PERMISSION_UNRESOLVED')
            elif 'UNKNOWN' in states:
                reasons.append('PERMISSION_UNRESOLVED')
            requested = descriptor + '->' + member
            sig, resolution = resolver.resolve(requested)
            if sig in methods and resolution in ('EXACT', 'INHERITED_DECLARATION'):
                (uncertain if entry_uncertain else confirmed).add(sig)
                records.append(dict(component=component['name'], method=sig,
                    status='UNCERTAIN' if entry_uncertain else 'CONFIRMED_CONFIGURATION',
                    configuration_reasons=reasons,
                    inherited=sig != requested, resolution=resolution))
            elif resolution in ('DECLARED_NO_BODY', 'UNKNOWN_DECLARATION', 'HIERARCHY_CYCLE'):
                records.append(dict(component=component['name'], method=sig,
                                    status='UNRESOLVED', resolution=resolution, inherited=sig != requested))
    diagnostics.extend(resolver.diagnostics)
    uncertain -= confirmed
    return dict(confirmed=sorted(confirmed), uncertain=sorted(uncertain), records=records,
                diagnostics=sorted(set(diagnostics)))


def external_entries(manifest: dict, methods: dict, hierarchy=None, method_index=()) -> set[str]:
    """Only configuration-confirmed unprotected entries; possible entries are separate."""
    return set(entry_catalog(manifest, methods, hierarchy, method_index)['confirmed'])
