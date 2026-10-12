from hashlib import sha256
import json
import logging
from pathlib import Path

from analyzer.app.jobs import Cancellation
from analyzer.app.settings import Settings, data_dir
from analyzer.app.project_manager import write_json
from analyzer.backends.base import AnalysisBackend, BackendError
from analyzer.core.models import Program
from analyzer.core.graph import verify_native_xref, DeclarationResolver
from analyzer.backends.jeb.session import JebSession
from analyzer.backends.jeb.protocol import decode_java_text

log = logging.getLogger(__name__)


def file_hash(path: Path, cancel: Cancellation | None = None) -> str:
    cancel = cancel or Cancellation()
    cancel.check()
    digest = sha256()
    with path.open('rb') as stream:
        while True:
            cancel.check()
            block = stream.read(1024 * 1024)
            cancel.check()
            if not block:
                break
            digest.update(block)
    cancel.check()
    return digest.hexdigest()


class JebBackend(AnalysisBackend):
    def __init__(self, settings: Settings):
        self.settings = settings
        self.home = Path(settings.jeb_path).resolve() if settings.jeb_path else None
        self.program = Program()
        self.input_path: Path | None = None
        self.script = Path(__file__).parent / 'scripts' / 'AOSEyeBridge.py'
        version = self.home / 'bin' / 'VERSION.TXT' if self.home else None
        self.version = version.read_text().strip() if version and version.exists() else 'unknown'
        self.session = JebSession(settings)
        self.session_info = {}
        self.capabilities = {}
        self.input_sha256 = ''

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _run(self, operation: str, cancel: Cancellation, receive=None, **kwargs) -> dict:
        self.session.heap_mib = self.settings.jvm_heap_mib
        response = self.session.request(operation, cancel, receive=receive, **kwargs)
        self.session_info = dict(response.get('session', {}), pid=self.session.pid)
        self.capabilities.update(response.get('capabilities', {}))
        self.program.capabilities.update(self.capabilities)
        return response

    def probe(self, cancel: Cancellation) -> dict:
        response = self._run('probe', cancel)
        return dict(path=str(self.home), version=self.version, status='Connected',
                    capabilities=response['capabilities'], session=self.session_info)

    def load(self, path: Path, cancel: Cancellation) -> Program:
        self.input_path = path.resolve()
        self.input_sha256 = file_hash(path, cancel)
        # Check current runtime access even when serving a normalized disk cache.
        self.probe(cancel)
        key = sha256((self.input_sha256 + self.version + file_hash(self.script, cancel) +
                      file_hash(self.script.with_name('CoreRunner.py'), cancel) +
                      file_hash(self.script.with_name('ExportBudget.py'), cancel) +
                      file_hash(self.script.with_name('PhaseTrace.py'), cancel) +
                      file_hash(self.script.with_name('IndexPriority.py'), cancel) + self.settings.index_order +
                      file_hash(Path(__file__).parents[1] / 'index_priority.py', cancel) +
                      str(self.settings.max_methods) + ':' + str(self.settings.max_export_mib) + ':' +
                      str(self.settings.max_index_entries) + ':' + str(self.settings.max_index_mib)).encode()).hexdigest()
        cache = data_dir() / 'cache' / (key + '.json')
        cancel.check()
        if self.settings.cache_enabled and cache.exists():
            try:
                self.program = Program.from_dict(json.loads(cache.read_text(encoding='utf-8')))
                return self.program
            except (ValueError, TypeError, KeyError):
                log.warning('Invalid cache; re-indexing')
        def receive(response, records):
            limit = self.settings.max_export_mib * 1024 * 1024
            if records.stat().st_size > limit:
                raise BackendError('Method stream exceeds configured byte budget')
            program = Program.from_dict(response['program'])
            consumed = 0
            with records.open('rb') as stream:
                while True:
                    cancel.check()
                    line = stream.readline(limit - consumed + 1)
                    if not line:
                        break
                    consumed += len(line)
                    if consumed > limit:
                        raise BackendError('Method stream exceeds configured byte budget')
                    value = json.loads(line, object_hook=decode_java_text)
                    method = Program.from_dict({'methods': {value['signature']: value}}).methods[value['signature']]
                    program.methods[method.signature] = method
            response['normalized_program'] = program
            return response
        hints, priority_error = {}, None
        if self.settings.index_order == 'manifest-first':
            from analyzer.backends.index_priority import manifest_hints
            try:
                inventory = self._run('resources', cancel, **self._input_request(cancel))
                hints = manifest_hints(inventory['manifest'])
            except (BackendError, OSError, ValueError, KeyError) as exc:
                priority_error = 'Manifest priority hints unavailable; native order used: ' + str(exc)
        response = self._run('index', cancel, receive=receive, input=str(self.input_path), input_sha256=self.input_sha256,
                             index_order=self.settings.index_order if priority_error is None else 'native', **hints,
                             max_methods=self.settings.max_methods,
                             max_export_bytes=self.settings.max_export_mib * 1024 * 1024,
                             max_index_entries=self.settings.max_index_entries,
                             max_index_bytes=self.settings.max_index_mib * 1024 * 1024)
        self.program = response['normalized_program']
        if priority_error:
            self.program.diagnostics.append(priority_error)
        if self.settings.cache_enabled:
            write_json(cache, self.program, compact=True)
        return self.program

    def get_decompiled_source(self, method: str, cancel: Cancellation) -> str:
        item = self.program.methods[method]
        request = self._input_request(cancel)
        if not item.source:
            item.source = self._method_request('decompile', method, cancel, request)['source']
        return item.source

    def preview_call_target(self, caller: str, offset: int, cancel: Cancellation, max_bytes=262144) -> dict:
        """Read-only, one direct/static callee candidate. Never merge into saved evidence."""
        from analyzer.core.models import Method
        from analyzer.core.input_validation import validate
        if type(max_bytes) is not int or not 1 <= max_bytes <= 1048576:
            raise ValueError('Candidate byte limit must be 1..1048576')
        cancel.check()
        if not self.input_sha256:
            raise BackendError('Candidate lookup requires the saved original input fingerprint')
        source = self.program.methods.get(caller)
        if source is None or not source.unit or type(offset) is not int or offset < 0:
            raise ValueError('Known caller unit and exact offset required')
        sites = []
        for n, instruction in enumerate(source.instructions):
            if n % 256 == 0:
                cancel.check()
            if instruction.offset == offset:
                sites.append(instruction)
        if len(sites) != 1 or sites[0].opcode not in ('invoke-static', 'invoke-static/range', 'invoke-direct', 'invoke-direct/range'):
            raise ValueError('Only unique direct/static call sites are supported')
        target = sites[0].target
        if not target or target in self.program.methods:
            raise ValueError('Target missing or already retained')
        rows = []
        for n, row in enumerate(self.program.method_index):
            if n % 256 == 0:
                cancel.check()
            if row.get('signature') == target and row.get('declared') is not False:
                rows.append(row)
        if not rows or any(r.get('declared') is not True or not r.get('unit') or r.get('has_code') is not True for r in rows):
            raise ValueError('Target requires a known code declaration and unit')
        units = {r['unit'] for r in rows}
        if len(units) != 1:
            raise ValueError('Ambiguous target units')
        unit = next(iter(units))
        request = self._input_request(cancel)
        self.session.heap_mib = self.settings.jvm_heap_mib
        # Avoid _run: its capability merge would mutate the saved program.
        response = self.session.request('method_candidate', cancel, **request, method=target,
                                        unit=unit, max_candidate_bytes=max_bytes)
        cancel.check()
        if response.get('byte_limit') != max_bytes:
            raise BackendError('Candidate budget response mismatch')
        if response.get('status') == 'BUDGET_EXCEEDED' and 'method' not in response:
            return dict(status='BUDGET_EXCEEDED', byte_limit=max_bytes)
        if response.get('status') != 'CANDIDATE':
            raise BackendError('Invalid candidate response')
        value = response.get('method')
        validate(value, Method, cancel=cancel)
        if value.get('signature') != target or value.get('unit') != unit:
            raise BackendError('Candidate identity mismatch')
        size = len((json.dumps(value, ensure_ascii=True) + '\n').encode('ascii'))
        if size > max_bytes or type(response.get('encoded_bytes')) is not int or response['encoded_bytes'] != size:
            raise BackendError('Candidate byte accounting mismatch')
        cancel.check()
        return dict(status='CANDIDATE', method=value, encoded_bytes=size, byte_limit=max_bytes,
                    input_sha256=self.input_sha256, caller=caller, offset=offset,
                    caller_unit=source.unit, opcode=sites[0].opcode,
                    scope='Single direct/static target; not merged or reanalyzed')

    def _input_request(self, cancel: Cancellation | None = None) -> dict:
        if self.input_path is None:
            raise BackendError('Open the original APK/DEX before requesting live JEB evidence')
        try:
            fingerprint = file_hash(self.input_path, cancel)
        except FileNotFoundError as exc:
            raise BackendError('Original APK/DEX missing or changed; re-analyze before requesting live evidence') from exc
        if self.input_sha256 and fingerprint != self.input_sha256:
            raise BackendError('Original APK/DEX missing or changed; re-analyze before requesting live evidence')
        self.input_sha256 = fingerprint
        return dict(input=str(self.input_path), input_sha256=fingerprint)

    def _method_request(self, operation, method, cancel, request, **kwargs):
        cancel.check()
        return self._run(operation, cancel, **request, method=method,
                         unit=self.program.methods[method].unit, **kwargs)

    def get_ast(self, method: str, cancel: Cancellation | None = None) -> dict:
        item = self.program.methods[method]
        cancel = cancel or Cancellation()
        request = self._input_request(cancel)
        if not item.ast:
            response = self._method_request('ast', method, cancel, request, max_nodes=5000)
            item.ast, item.source = response['ast'], response['source']
        return item.ast

    def get_jeb_xrefs(self, element: str, cancel: Cancellation, offset=0, limit=300) -> dict:
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError('Invalid XREF page bounds')
        response = self._run('xref', cancel, **self._input_request(cancel), element=element,
                             offset=offset, limit=limit)
        resolver = DeclarationResolver(self.program)
        return dict(items=[verify_native_xref(self.program, element, ref, resolver) for ref in response['xrefs']],
                    total=response['total'], offset=offset,
                    evidence_origin='JEB getCrossReferences')

    def resolve_network_xml(self, reference: str, cancel: Cancellation) -> dict:
        return self._run('network_resource', cancel, **self._input_request(cancel), reference=reference)

    def resolve_named_storage_xml(self, reference: str, cancel: Cancellation) -> dict:
        from analyzer.backends.raw_names import dump_resources, select_resource_name
        self._input_request(cancel)
        if not self.settings.aapt2_path:
            raise ValueError('Named storage XML mapping requires configured aapt2')
        executable = Path(self.settings.aapt2_path)
        if not executable.is_absolute() or not executable.is_file():
            raise ValueError('Configured aapt2 executable is missing or not an absolute file path')
        selected = select_resource_name(dump_resources(executable, self.input_path, cancel), reference, 'xml')
        decoded = self.resolve_network_xml('@%08x' % selected['resource_id'], cancel)
        cancel.check()
        if decoded.get('resource_id') != selected['resource_id'] or decoded.get('configuration') != 'default-only':
            raise ValueError('Decoded XML identity/configuration mismatch')
        return dict(decoded, reference=reference, name_origin=selected['name_origin'], package=selected['package'])

    def resolve_ca_resource(self, reference: str, cancel: Cancellation) -> dict:
        from analyzer.analyzers.network_certificates import select_raw_resource
        from analyzer.backends.raw_names import dump_resources, select_raw_name
        request = self._input_request(cancel)
        selected = None
        if reference.startswith('@raw/'):
            if not self.settings.aapt2_path:
                return dict(status='NAMED_RESOLUTION_DISABLED')
            executable = Path(self.settings.aapt2_path)
            if not executable.is_absolute() or not executable.is_file():
                raise ValueError('Configured aapt2 executable is missing or not an absolute file path')
            selected = select_raw_name(dump_resources(executable, self.input_path, cancel), reference)
            reference = '@%08x' % selected['resource_id']
            request = self._input_request(cancel)
        inventory = self._run('resources', cancel, **request, resource_type='raw')
        result = select_raw_resource(inventory, reference)
        if selected:
            result.update(reference=selected['reference'], name_origin=selected['name_origin'], package=selected['package'])
        return result
