from abc import ABC, abstractmethod
from pathlib import Path
from analyzer.app.jobs import Cancellation
from analyzer.core.models import Program
from analyzer.core.graph import DeclarationResolver, reference_query


class BackendError(RuntimeError):
    pass


class UnsupportedCapability(BackendError):
    pass


class AnalysisBackend(ABC):
    program: Program

    @abstractmethod
    def probe(self, cancel: Cancellation) -> dict: ...

    @abstractmethod
    def load(self, path: Path, cancel: Cancellation) -> Program: ...

    def get_classes(self):
        return self.program.classes

    def get_methods(self):
        return self.program.methods.values()

    def open_apk(self, path: Path, cancel: Cancellation | None = None) -> Program:
        return self.load(path, cancel or Cancellation())

    def get_method(self, method_id: str):
        return self.program.methods[method_id]

    def get_dex_units(self):
        return self.program.dex_units

    def get_method_bytecode(self, method_id: str):
        return self.get_method(method_id).instructions

    def get_fields(self):
        return self.program.fields

    def get_callees(self, method: str):
        resolver = DeclarationResolver(self.program)
        return sorted({resolver.target(i.target) for i in self.program.methods[method].instructions
                       if i.opcode.startswith("invoke") and i.target})

    def get_callers(self, method: str):
        resolver = DeclarationResolver(self.program)
        return sorted({m.signature for m in self.get_methods()
                       if any(i.opcode.startswith('invoke') and method in (i.target, resolver.target(i.target))
                              for i in m.instructions)})

    def get_call_graph(self, method: str | None = None, limit=300, cancel=None):
        return reference_query(self.program, method, limit, cancel)

    def get_xrefs(self, element: str):
        resolver = DeclarationResolver(self.program)
        return [dict(method=m.signature, offset=i.offset, opcode=i.opcode, unit=m.unit,
                     raw_declared_target=i.target, resolved_declared_target=resolver.target(i.target)
                     if i.opcode.startswith('invoke') else i.target)
                for m in self.get_methods() for i in m.instructions
                if i.target == element or (i.opcode.startswith('invoke') and resolver.target(i.target) == element)]

    def get_cfg(self, method: str):
        return self.program.methods[method].cfg

    def get_ast(self, method: str, cancel: Cancellation | None = None):
        raise UnsupportedCapability("This backend does not support normalized Java AST export")

    @abstractmethod
    def get_decompiled_source(self, method: str, cancel: Cancellation) -> str: ...

    def close(self):
        """Release runtime resources; normalized evidence may remain usable."""
