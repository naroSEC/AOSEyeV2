import importlib.util
import io
from pathlib import Path
import tarfile

import pytest

spec = importlib.util.spec_from_file_location('source_distribution',
    Path(__file__).parents[1] / 'tools/validate_source_distribution.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def make_archive(tmp_path, extra=None, kind=None):
    path = tmp_path / 'source.tar.gz'
    with tarfile.open(path, 'w:gz') as archive:
        for name in sorted(module.REQUIRED):
            member = tarfile.TarInfo('aoseye-0.1.0/' + name)
            member.size = 1
            archive.addfile(member, io.BytesIO(b'x'))
        if extra:
            member = tarfile.TarInfo(extra)
            if kind:
                member.type = kind
                member.linkname = 'outside'
            archive.addfile(member)
    return path


def test_source_archive_boundary(tmp_path):
    result = module.assess(make_archive(tmp_path))
    assert result['status'] == 'SOURCE_BOUNDARY_PASS'
    assert result['files'] == len(module.REQUIRED)


@pytest.mark.parametrize('extra,kind', [
    ('aoseye-0.1.0/private.apk', None), ('aoseye-0.1.0/tests/sample.apk', None),
    ('aoseye-0.1.0/.codex-remote-attachments/sample.py', None),
    ('aoseye-0.1.0/docs/project.json', None), ('aoseye-0.1.0/src/analyzer/.env', None),
    ('aoseye-0.1.0/LICENSE', None), ('aoseye-0.1.0/../secret.py', None),
    ('/absolute.py', None), ('other/LICENSE', None),
    ('aoseye-0.1.0/docs/C:drive.md', None), ('aoseye-0.1.0/docs/line\nbreak.md', None),
    ('.hidden/LICENSE', None),
    ('aoseye-0.1.0/tools/link.py', tarfile.SYMTYPE),
    ('aoseye-0.1.0/tools/link.py', tarfile.LNKTYPE),
    ('aoseye-0.1.0/tools/link.py', tarfile.FIFOTYPE),
])
def test_source_archive_rejects_unexpected_members(tmp_path, extra, kind):
    with pytest.raises(ValueError):
        module.assess(make_archive(tmp_path, extra, kind))
