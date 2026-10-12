"""Read-only sdist boundary validation, without extraction or publication.

Checks package contents, not text secrets or permission to redistribute all sources.
"""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import tarfile

ROOT_FILES = {'LICENSE', 'THIRD_PARTY_NOTICES.md', 'PACKAGE_README.md', 'README.md',
              'CONTRIBUTING.md', 'SECURITY.md', 'pyproject.toml', 'MANIFEST.in',
              'PKG-INFO', 'setup.cfg'}
REQUIRED = {'LICENSE', 'THIRD_PARTY_NOTICES.md', 'PACKAGE_README.md', 'pyproject.toml',
            'CONTRIBUTING.md', 'SECURITY.md', 'src/analyzer/__init__.py'}
LIMIT = 8 * 1024 * 1024


def allowed(path):
    parts = path.parts
    if any(p.startswith('.') or p == '__pycache__' for p in parts):
        return False
    if len(parts) == 1:
        return path.name in ROOT_FILES
    if parts[:2] == ('src', 'analyzer'):
        return path.suffix in {'.py', '.qml', '.yaml'}
    if parts[:2] == ('src', 'aoseye.egg-info'):
        return len(parts) == 3 and path.name in {'PKG-INFO', 'SOURCES.txt', 'dependency_links.txt',
            'entry_points.txt', 'requires.txt', 'top_level.txt'}
    if parts[0] == 'tests':
        return path.suffix in {'.py', '.java', '.xml'}
    if parts[0] == 'tools':
        return len(parts) == 2 and path.suffix == '.py'
    if parts[0] == 'docs':
        return path.suffix == '.md' or str(path) == 'docs/release-acceptance.template.json'
    return False


def assess(archive_path):
    seen, files, roots = set(), set(), set()
    total = 0
    with tarfile.open(archive_path, 'r:gz') as archive:
        for index, member in enumerate(archive):
            if index >= 10000:
                raise ValueError('Source member count limit')
            name = member.name
            path = PurePosixPath(name)
            if ('\\' in name or ':' in name or any(ord(c) < 32 for c in name)
                    or name.startswith('.') or path.is_absolute()
                    or any(p in ('', '.', '..') for p in name.split('/'))
                    or name in seen or not (member.isdir() or member.isfile())):
                raise ValueError('Unsafe or duplicate source member')
            seen.add(name)
            roots.add(path.parts[0])
            if member.isdir():
                continue
            relative = PurePosixPath(*path.parts[1:])
            if len(path.parts) < 2 or not allowed(relative):
                raise ValueError('Unexpected source member')
            total += member.size
            if member.size < 0 or member.size > LIMIT or total > 64 * 1024 * 1024:
                raise ValueError('Source size limit')
            # Force gzip/tar payload validation, without writing extracted files.
            with archive.extractfile(member) as stream:
                if len(stream.read(LIMIT + 1)) != member.size:
                    raise ValueError('Truncated source member')
            files.add(str(relative))
    if len(roots) != 1 or not REQUIRED <= files:
        raise ValueError('Missing required source files or multiple roots')
    with archive_path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(status='SOURCE_BOUNDARY_PASS', sha256=digest, files=len(files), bytes=total,
                scope='Archive boundary only; not a secrets scan, license audit or release approval')


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    try:
        report = assess(args.archive)
    except Exception as exc:
        print(json.dumps(dict(status='BLOCKED', error_type=type(exc).__name__)))
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
