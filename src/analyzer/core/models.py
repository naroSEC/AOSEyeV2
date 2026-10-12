from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import Any


class Category(StrEnum):
    MANIFEST = "MANIFEST"
    COMPONENT = "COMPONENT"
    IPC = "IPC"
    DEEPLINK = "DEEPLINK"
    WEBVIEW = "WEBVIEW"
    STORAGE = "STORAGE"
    SECRETS = "SECRETS"
    CRYPTO = "CRYPTO"
    NETWORK = "NETWORK"
    AUTH = "AUTH"
    DATAFLOW = "DATAFLOW"
    DYNAMIC = "DYNAMIC"
    DEPENDENCY = "DEPENDENCY"
    RESILIENCE = "RESILIENCE"
    PRIVACY = "PRIVACY"
    INFO = "INFO"


class FindingType(StrEnum):
    VULNERABILITY = "VULNERABILITY"
    WEAKNESS = "WEAKNESS"
    EXPOSURE = "EXPOSURE"
    HARDENING = "HARDENING"
    REVIEW = "REVIEW"
    INFORMATION = "INFORMATION"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(StrEnum):
    CERTAIN = "CERTAIN"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Verification(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POTENTIAL = "POTENTIAL"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass
class Location:
    class_name: str = ""
    method: str = ""
    offset: int | None = None
    file: str = ""


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    category: str
    type: str = FindingType.REVIEW
    severity: str = Severity.INFO
    confidence: str = Confidence.LOW
    verification: str = Verification.MANUAL_REVIEW
    analysis_level: str = "L1"
    location: Location = field(default_factory=Location)
    source: str = ""
    sink: str = ""
    data_flow: list[dict] = field(default_factory=list)
    attack_path: list[dict] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    decompiled_code: str = ""
    bytecode: str = ""
    related_methods: list[str] = field(default_factory=list)
    validation: dict[str, str] = field(default_factory=dict)
    review: dict = field(default_factory=dict)
    recommendation: str = "Review the evidence and verify runtime preconditions."
    standards: dict[str, list[str]] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self):
        if not self.id:
            key = repr((self.rule_id, asdict(self.location), self.source, self.sink))
            self.id = sha256(key.encode()).hexdigest()[:20]


@dataclass
class Instruction:
    offset: int
    opcode: str
    registers: list[int] = field(default_factory=list)
    defs: list[int] = field(default_factory=list)
    uses: list[int] = field(default_factory=list)
    target: str = ""
    literal: Any = None
    text: str = ""
    successors: list[int] = field(default_factory=list)
    normal_successors: list[int] | None = None


@dataclass
class Method:
    signature: str
    class_name: str = ""
    parameter_registers: list[int] = field(default_factory=list)
    instructions: list[Instruction] = field(default_factory=list)
    cfg: list[dict] = field(default_factory=list)
    source: str = ""
    unit: str = ""
    diagnostics: list[str] = field(default_factory=list)
    ast: dict = field(default_factory=dict)
    exception_status: str = 'UNKNOWN'
    exception_regions: list[dict] = field(default_factory=list)


@dataclass
class Program:
    methods: dict[str, Method] = field(default_factory=dict)
    classes: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    class_hierarchy: dict[str, str] = field(default_factory=dict)
    class_interfaces: dict[str, list[str]] = field(default_factory=dict)
    dex_units: list[dict] = field(default_factory=list)
    method_index: list[dict] = field(default_factory=list)
    class_index: list[dict] = field(default_factory=list)
    field_index: list[dict] = field(default_factory=list)
    manifest: str = ""
    diagnostics: list[str] = field(default_factory=list)
    capabilities: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: dict, *, consume=False, cancel=None) -> Program:
        """consume is only for an owned, already validated deserialization buffer."""
        if cancel:
            cancel.check()
        methods = {}
        source = value.get("methods", {})
        # Snapshot keys preserves index order while freeing each raw method DTO.
        entries = ((sig, source.pop(sig)) for sig in list(source)) if consume else source.items()
        for sig, item in entries:
            if cancel:
                cancel.check()
            item = dict(item)
            instructions = []
            for n, instruction in enumerate(item.get("instructions", [])):
                if cancel and n % 256 == 0:
                    cancel.check()
                instructions.append(Instruction(**instruction))
            item["instructions"] = instructions
            methods[sig] = Method(**item)
        return cls(methods=methods, **{k: value[k] for k in
                   ("classes", "fields", "class_hierarchy", "class_interfaces", "dex_units", "method_index", "class_index", "field_index", "manifest", "diagnostics", "capabilities") if k in value})


@dataclass
class AnalysisResult:
    input_path: str
    sha256: str
    findings: list[Finding] = field(default_factory=list)
    program: Program = field(default_factory=Program)
    manifest: dict = field(default_factory=dict)
    files: list[dict] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)
    complete: bool = False
    schema_version: int = 1

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict, *, consume=False, cancel=None, progress=None) -> AnalysisResult:
        if cancel:
            cancel.check()
        if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value['schema_version'] != 1:
            raise ValueError("Unsupported project schema")
        from analyzer.core.input_validation import validate_project
        if progress:
            progress(45, 'Validating project schema')
        validate_project(value, cancel=cancel)
        if progress:
            progress(80, 'Building project model')
        if cancel:
            cancel.check()
        value = dict(value)
        value["program"] = Program.from_dict(value.get("program", {}), consume=consume, cancel=cancel)
        findings = []
        for f in value.get("findings", []):
            if cancel:
                cancel.check()
            findings.append(Finding(**{**f, "location": Location(**f.get("location", {}))}))
        value["findings"] = findings
        if cancel:
            cancel.check()
        return cls(**value)
