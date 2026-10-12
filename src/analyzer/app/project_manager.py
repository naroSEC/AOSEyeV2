import json
import os
import tempfile
from dataclasses import is_dataclass, fields
from pathlib import Path
from analyzer.core.models import AnalysisResult
from analyzer.core.input_validation import read_json

MAX_PROJECT_BYTES = 512 * 1024 * 1024


class ModelEncoder(json.JSONEncoder):
    def default(self, value):
        if is_dataclass(value):
            return {f.name: getattr(value, f.name) for f in fields(value)}
        return super().default(value)


def write_json(path: Path, value, compact=False, max_bytes=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".aoseye-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=True, indent=None if compact else 2,
                      separators=(',', ':') if compact else None, cls=ModelEncoder, allow_nan=False)
            stream.flush()
            if max_bytes is not None and stream.tell() > max_bytes:
                raise ValueError(f'JSON file exceeds {max_bytes} byte limit')
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def save_project(path: Path, result: AnalysisResult):
    write_json(path, result, compact=True, max_bytes=MAX_PROJECT_BYTES)


def open_project(path: Path, cancel=None, progress=None) -> AnalysisResult:
    # This fresh JSON tree belongs exclusively to the loader. Public from_dict
    # calls still preserve their input by default; all validation runs first.
    if cancel:
        cancel.check()
    if progress:
        progress(0, 'Reading project JSON')
    return AnalysisResult.from_dict(read_json(path, MAX_PROJECT_BYTES, cancel=cancel),
                                    consume=True, cancel=cancel, progress=progress)
