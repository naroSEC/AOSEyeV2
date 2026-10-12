from hashlib import sha256
import io
from pathlib import Path

import pytest

from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.settings import Settings
from analyzer.backends.jeb.backend import file_hash, JebBackend


def test_cancelled_hash_does_not_open_missing_file(tmp_path):
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        file_hash(tmp_path / 'missing', token)


@pytest.mark.parametrize('size', [0, 1, 1024 * 1024 + 7])
def test_hash_matches_sha256(tmp_path, size):
    path = tmp_path / 'input'
    data = b'x' * size
    path.write_bytes(data)
    assert file_hash(path) == sha256(data).hexdigest()


def test_cancel_during_read_closes_stream_without_second_read(monkeypatch):
    token = Cancellation()
    class Reader(io.BytesIO):
        reads = 0
        def read(self, size):
            assert size == 1024 * 1024
            self.reads += 1
            token.cancel()
            return super().read(size)
    stream = Reader(b'x' * (2 * 1024 * 1024))
    monkeypatch.setattr(Path, 'open', lambda *args, **kwargs: stream)
    with pytest.raises(Cancelled):
        file_hash(Path('synthetic'), token)
    assert stream.closed and stream.reads == 1


def test_backend_hash_cancel_preserves_fingerprint_and_never_dispatches(tmp_path, monkeypatch):
    backend = JebBackend(Settings(jeb_path=str(tmp_path)))
    backend.input_path = tmp_path / 'missing'
    backend.input_sha256 = 'previous fingerprint'
    token = Cancellation()
    token.cancel()
    monkeypatch.setattr(backend, '_run', lambda *a, **k: pytest.fail('Must not dispatch'))
    with pytest.raises(Cancelled):
        backend.get_jeb_xrefs('field', token)
    assert backend.input_sha256 == 'previous fingerprint'
