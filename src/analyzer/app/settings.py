from dataclasses import asdict, dataclass, field
from pathlib import Path
import os
from analyzer.core.input_validation import read_json, validate

MAX_SETTINGS_BYTES = 64 * 1024


def data_dir() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local/share"))) / "AOSEye"


@dataclass
class Settings:
    jeb_path: str = field(default_factory=lambda: os.environ.get("AOSEYE_JEB_PATH", ""))
    java: str = "java"
    timeout_seconds: int = 900
    max_methods: int = 100000
    max_flow_steps: int = 100000
    max_call_depth: int = 8
    cache_enabled: bool = True
    aapt2_path: str = ""
    jvm_heap_mib: int = 4096
    max_export_mib: int = 64
    max_index_entries: int = 20000
    max_index_mib: int = 8
    index_order: str = 'native'

    def __post_init__(self):
        self.validate()

    def validate(self):
        validate(asdict(self), type(self))
        if self.index_order not in ('native', 'manifest-first'):
            raise ValueError('index_order must be native or manifest-first')
        if not 1 <= self.max_index_entries <= 200000 or not 1 <= self.max_index_mib <= 64:
            raise ValueError('Index limits: entries 1–200000 per kind; encoded size 1–64 MiB')
        if not 1 <= self.max_export_mib <= 256:
            raise ValueError('max_export_mib must be between 1 and 256 MiB')
        if not 512 <= self.jvm_heap_mib <= 16384:
            raise ValueError('jvm_heap_mib must be between 512 and 16384 MiB')
        if self.aapt2_path and (not Path(self.aapt2_path).is_absolute()
                or any(c in self.aapt2_path for c in ('\x00', '\r', '\n'))):
            raise ValueError('aapt2_path must be empty or an absolute executable path')
        for key in ('jeb_path', 'java'):
            value = getattr(self, key)
            if key == 'jeb_path' and value == '':
                continue  # Unconfigured GUI/report viewing is supported; analysis requires a path.
            if not value.strip() or any(c in value for c in ('\x00', '\r', '\n')):
                raise ValueError('Invalid settings path/command: ' + key)
        for key, upper in (('timeout_seconds', 86400), ('max_methods', 1000000),
                           ('max_flow_steps', 10000000), ('max_call_depth', 128)):
            if not 1 <= getattr(self, key) <= upper:
                raise ValueError(f'{key} must be between 1 and {upper}')

    @classmethod
    def load(cls, path: Path | None = None):
        path = path or data_dir() / "settings.json"
        if not path.exists():
            return cls()
        value = read_json(path, MAX_SETTINGS_BYTES)
        validate(value, cls)
        return cls(**value)

    def save(self, path: Path | None = None):
        from analyzer.app.project_manager import write_json
        self.validate()
        write_json(path or data_dir() / "settings.json", asdict(self), max_bytes=MAX_SETTINGS_BYTES)
