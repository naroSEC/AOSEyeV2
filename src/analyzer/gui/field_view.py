"""Compact JSON layout for bounded field pages without losing raw evidence."""
import json


def field_page_text(page):
    header = json.dumps({key: value for key, value in page.items() if key != 'items'},
                        ensure_ascii=True, indent=2)
    rows = ',\n'.join('    ' + json.dumps(item, ensure_ascii=True) for item in page['items'])
    return header[:-2] + ',\n  "items": [\n' + rows + '\n  ]\n}'
