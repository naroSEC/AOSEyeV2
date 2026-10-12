"""Manifest names are priority hints, not code ownership or entrypoint proof."""
import re
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException


def manifest_hints(xml):
    if not isinstance(xml, str) or len(xml.encode('utf-8')) > 1024 * 1024:
        raise ValueError('Manifest hint text budget/type invalid')
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ValueError('Manifest hint XML invalid or unsafe') from exc
    if root.tag != 'manifest' or len(list(root.iter())) > 20000:
        raise ValueError('Manifest hint root/node budget invalid')
    package = root.get('package', '')
    valid = lambda s: bool(re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*', s, flags=re.ASCII))
    package = package if valid(package) else ''
    prefix = 'L' + package.replace('.', '/') + '/' if package else ''
    namespace = '{http://schemas.android.com/apk/res/android}'
    classes = set()
    app = root.find('application')
    if app is not None:
        nodes = [(app, 'name'), (app, 'appComponentFactory')]
        for node in app:
            if node.tag in ('activity', 'service', 'receiver', 'provider'):
                nodes.append((node, 'name'))
            elif node.tag == 'activity-alias':
                nodes.append((node, 'targetActivity'))
        for node, attribute in nodes:
            raw = node.get(namespace + attribute, '')
            if not raw:
                continue
            name = package + raw if raw.startswith('.') and package else package + '.' + raw if '.' not in raw and package else raw
            if valid(name):
                classes.add('L' + name.replace('.', '/') + ';')
            if len(classes) > 2048:
                raise ValueError('Manifest class hint budget exceeded')
    return dict(priority_classes=sorted(classes), priority_package=prefix)
